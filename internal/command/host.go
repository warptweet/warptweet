package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const defaultHostListenPort uint16 = 2222

func runHost(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("host", stderr)
	to := onceStringFlag{name: "--to"}
	name := onceStringFlag{name: "--name"}
	out := onceStringFlag{name: "--out"}
	listen := onceStringFlag{name: "--listen"}
	stdoutInvite := onceBoolFlag{name: "--stdout"}
	noInvite := onceBoolFlag{name: "--no-invite"}
	asJSON := onceBoolFlag{name: "--json"}
	accessFor := onceStringFlag{name: "--access-for"}
	flags.Var(&to, "to", "target port or ip:port")
	flags.Var(&name, "name", "invite client label")
	flags.Var(&out, "out", "exact invite output path")
	flags.Var(&listen, "listen", "numeric server listen address:port")
	flags.Var(&stdoutInvite, "stdout", "print invite JSON only; do not write a file")
	flags.Var(&noInvite, "no-invite", "bootstrap host without minting an invite")
	flags.Var(&asJSON, "json", "emit JSON")
	flags.Var(&accessFor, "access-for", "authorization duration such as 30d")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if to.value == "" {
		return errors.New("host requires --to <port|ip:port>")
	}
	if stdoutInvite.value && noInvite.value {
		return errors.New("host --stdout cannot be combined with --no-invite")
	}
	if stdoutInvite.value && out.value != "" {
		return errors.New("host --stdout cannot be combined with --out")
	}
	if stdoutInvite.value && asJSON.value {
		return errors.New("host --stdout cannot be combined with --json")
	}
	if noInvite.value && (out.value != "" || name.value != "") {
		return errors.New("host --no-invite cannot be combined with invite naming flags")
	}

	targetEndpoint, err := parseHostTarget(to.value)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}
	policy, err := grant.LoadPolicy(installlayout.HostAuthorizationPolicyPath)
	if err != nil {
		return fmt.Errorf("host authorization policy: %w", err)
	}
	var requestedDuration int64
	if accessFor.value != "" {
		parsed, err := grant.ParseAccessDuration(accessFor.value)
		if err != nil {
			return fmt.Errorf("access-for: %w", err)
		}
		seconds, err := grant.Seconds(parsed)
		if err != nil {
			return fmt.Errorf("access-for: %w", err)
		}
		requestedDuration = seconds
	}
	authorizationSeconds, err := grant.ResolveDuration(policy, requestedDuration)
	if err != nil {
		if accessFor.value != "" {
			return fmt.Errorf("access-for: %w", err)
		}
		return fmt.Errorf("host authorization policy: %w", err)
	}
	listenEndpoint, err := resolveHostListen(listen.value)
	if err != nil {
		return err
	}

	if err := ensureHostDirectories(); err != nil {
		return err
	}
	var (
		hostPublicKey                string
		createdHostKey               bool
		enrollmentPin                string
		createdEnrollmentIdentity    bool
		renewedEnrollmentCertificate bool
		manifest                     server.Config
	)
	if err := withHostStateLock(func() error {
		if grant.ClockIsBlocked(installlayout.HostClockBlockedPath) {
			return outcome.New(outcome.CodeClockBlocked, "host clock: blocked until warptweet server clock-recover", "Run host clock recovery before minting invites", 1)
		}
		if _, err := grant.ObserveClock(installlayout.HostClockObservationPath, time.Now().UTC()); err != nil {
			if existing, loadErr := server.Load(installlayout.ServerManifestPath); loadErr == nil {
				if closeErr := enterBlockedClock(existing, err); closeErr != nil {
					return closeErr
				}
			}
			return fmt.Errorf("host clock: %w", err)
		}
		key, created, err := ensureHostIdentity(ctx)
		if err != nil {
			return err
		}
		hostPublicKey = key
		createdHostKey = created
		if err := ensureInviteSecret(); err != nil {
			return err
		}
		pin, createdTLS, renewedTLS, err := enrollment.EnsureTLSIdentity(
			installlayout.ServerEnrollmentTLSCertPath,
			installlayout.ServerEnrollmentTLSKeyPath,
			[]net.IP{net.IP(listenEndpoint.Addr().AsSlice())},
			time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("ensure enrollment TLS identity: %w", err)
		}
		enrollmentPin = pin
		createdEnrollmentIdentity = createdTLS
		renewedEnrollmentCertificate = renewedTLS
		if err := refuseHostTargetChange(targetEndpoint); err != nil {
			return err
		}
		written, writeErr := writeHostManifest(listenEndpoint, targetEndpoint)
		if writeErr != nil {
			return writeErr
		}
		manifest = written
		return nil
	}); err != nil {
		return err
	}
	if err := reconcileExpiredGrants(manifest, time.Now().UTC()); err != nil {
		return fmt.Errorf("reconcile expired grants: %w", err)
	}
	if err := reconcileManagedAuthorizations(manifest); err != nil {
		return fmt.Errorf("reconcile managed authorizations: %w", err)
	}
	dataPlaneStatus, err := ensureSSHDStarted(ctx, manifest)
	if err != nil {
		return fmt.Errorf("start WarpTweet data plane: %w", err)
	}

	result := map[string]any{
		"status":        "ready",
		"target":        targetEndpoint.String(),
		"listen":        listenEndpoint.String(),
		"host_key_path": installlayout.ServerHostKeyPath,
		"manifest_path": installlayout.ServerManifestPath,
		"host_key":      map[string]any{"created": createdHostKey},
		"enrollment_tls": map[string]any{
			"created":     createdEnrollmentIdentity,
			"renewed":     renewedEnrollmentCertificate,
			"spki_sha256": enrollmentPin,
		},
		"dedicated_user": manifest.DedicatedUser,
		"profile_id":     manifest.ProfileID,
		"data_plane":     dataPlaneStatus,
	}
	fingerprint := sha256.Sum256([]byte(hostPublicKey))
	hostFingerprint := hex.EncodeToString(fingerprint[:])
	result["host_public_key_sha256"] = hostFingerprint

	if err := ensureMgmtListenStarted(); err != nil {
		return err
	}
	enrollStatus, err := applyEnrollListenStatus(result, listenEndpoint.Addr(), enrollmentPin)
	if err != nil {
		return err
	}

	if noInvite.value {
		if asJSON.value {
			return writeJSON(stdout, result)
		}
		return writeHostHuman(stdout, hostHumanOutput{
			Target:       targetEndpoint.String(),
			Listen:       listenEndpoint.String(),
			Fingerprint:  hostFingerprint,
			EnrollStatus: enrollStatus,
		})
	}

	label := name.value
	if label == "" {
		label = defaultHostLabel()
	}
	label = enrollment.SanitizeInviteLabel(label)

	invite, record, err := mintServerInvite(ctx, label, targetEndpoint, manifest, hostPublicKey, enrollmentPin, authorizationSeconds)
	if err != nil {
		return err
	}
	if err := enrollment.Store(inviteDirectory, record); err != nil {
		return err
	}
	raw, err := enrollment.Encode(invite)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	if stdoutInvite.value {
		_, err := stdout.Write(raw)
		return err
	}

	var invitePath string
	if out.value != "" {
		invitePath, err = enrollment.WriteInviteFileExact(out.value, raw)
	} else {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return cwdErr
		}
		invitePath, err = enrollment.WriteInviteFile(cwd, label, invite.InviteID, raw)
	}
	if err != nil {
		return err
	}

	result["invite_id"] = invite.InviteID
	result["invite_expires_at"] = invite.ExpiresAt
	result["authorization_duration_seconds"] = invite.AuthorizationDurationSeconds
	result["invite_path"] = invitePath
	result["invite_class"] = "confidential_bearer"
	result["client_name"] = label

	if asJSON.value {
		return writeJSON(stdout, result)
	}
	return writeHostHuman(stdout, hostHumanOutput{
		Target:               targetEndpoint.String(),
		Listen:               listenEndpoint.String(),
		Fingerprint:          hostFingerprint,
		InvitePath:           invitePath,
		InviteExpiresAt:      invite.ExpiresAt,
		AuthorizationSeconds: invite.AuthorizationDurationSeconds,
		EnrollStatus:         enrollStatus,
	})
}

func applyEnrollListenStatus(result map[string]any, listenAddr netip.Addr, enrollmentPin string) (string, error) {
	started, startErr := ensureEnrollListenStarted(listenAddr, enrollmentPin)
	if startErr != nil {
		result["enroll_listen_error"] = startErr.Error()
		return "error", fmt.Errorf("start enrollment listener: %w", startErr)
	}
	enrollStatus := "already_running"
	if started {
		enrollStatus = "started"
	}
	result["enroll_listen"] = enrollStatus
	result["enroll_port"] = enrollment.DefaultEnrollmentPort
	return enrollStatus, nil
}

type hostHumanOutput struct {
	Target               string
	Listen               string
	Fingerprint          string
	InvitePath           string
	InviteExpiresAt      string
	AuthorizationSeconds int64
	EnrollStatus         string
}

func writeHostHuman(stdout io.Writer, output hostHumanOutput) error {
	_, err := fmt.Fprintf(stdout, "host ready\ntarget   %s\nlisten   %s\nhost     SHA256:%s\n", output.Target, output.Listen, output.Fingerprint)
	if err != nil {
		return err
	}
	if output.InvitePath != "" {
		_, err = fmt.Fprintf(stdout, "invite   %s\nclass    confidential bearer; transfer authenticated and delete after use\n", output.InvitePath)
		if err != nil {
			return err
		}
	}
	if output.InviteExpiresAt != "" {
		_, err = fmt.Fprintf(stdout, "invite expires   %s\n", output.InviteExpiresAt)
		if err != nil {
			return err
		}
	}
	if output.AuthorizationSeconds > 0 {
		_, err = fmt.Fprintf(stdout, "authorization    %ds\n", output.AuthorizationSeconds)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "enroll   :%d (%s)\n", enrollment.DefaultEnrollmentPort, output.EnrollStatus)
	return err
}

func ensureEnrollListenStarted(listenAddr netip.Addr, enrollmentPin string) (started bool, err error) {
	endpoint := netip.AddrPortFrom(listenAddr, enrollment.DefaultEnrollmentPort)
	pidPath := filepath.Join(serverStateDirectory, "enroll-listen.pid")
	if enrollListenAlreadyRunning(endpoint, enrollmentPin) {
		return false, nil
	}

	// Prefer the packaged unit when present so confinement matches production.
	if handled, unitErr := tryStartEnrollUnit(endpoint, enrollmentPin); handled {
		return unitErr == nil, unitErr
	}

	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(serverStateDirectory, 0o700); err != nil {
		return false, err
	}
	logPath := filepath.Join(serverStateDirectory, "enroll-listen.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	cmd := exec.Command(self, "server", "enroll-listen", "--listen", endpoint.String())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = enrollListenSysProcAttr()
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return false, err
	}
	_ = os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600)
	// Detach: do not wait; close our log handle after child inherits it.
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
	}()
	// Brief readiness probe.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			_ = os.Remove(pidPath)
			_ = logFile.Close()
			return false, fmt.Errorf("enroll-listen exited before accepting: %w", err)
		}
		if probeEnrollmentEndpoint(endpoint, enrollmentPin) {
			return true, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A live process is not readiness. The pinned TLS endpoint is the contract.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		_ = os.Remove(pidPath)
		return false, fmt.Errorf("enroll-listen exited before accepting: %w", err)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = os.Remove(pidPath)
	return false, errors.New("enroll-listen remained alive but its pinned TLS endpoint did not become ready")
}

func tryStartEnrollUnit(endpoint netip.AddrPort, enrollmentPin string) (bool, error) {
	unitPath := "/lib/systemd/system/warptweet-enroll.service"
	if _, err := os.Stat(unitPath); err != nil {
		unitPath = "/usr/lib/systemd/system/warptweet-enroll.service"
		if _, err := os.Stat(unitPath); err != nil {
			return false, nil
		}
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, nil
	}
	cmd := exec.Command("systemctl", "start", "warptweet-enroll.service")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("start warptweet-enroll.service: %w", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if probeEnrollmentEndpoint(endpoint, enrollmentPin) {
			return true, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true, errors.New("warptweet-enroll.service started but its pinned TLS endpoint did not become ready")
}

const mgmtListenLockName = ".mgmt-listen.lock"

func ensureMgmtListenStarted() error {
	return enrollment.WithExclusiveLock(serverStateDirectory, mgmtListenLockName, startMgmtListenLocked)
}

func startMgmtListenLocked() error {
	endpoint := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", enrollment.DefaultManagementPort))
	if pid, err := packagedMgmtMainPID(); err == nil && processOwnsTCPListen(pid, endpoint) {
		return nil
	}
	if pid, err := readPIDFile(filepath.Join(serverStateDirectory, "mgmt-listen.pid")); err == nil && processOwnsTCPListen(pid, endpoint) {
		return nil
	}
	if packagedMgmtUnitPresent() {
		if err := startPackagedMgmtUnit(); err != nil {
			return err
		}
		return waitForOwnedMgmtListen(endpoint, packagedMgmtMainPID)
	}
	cmd, err := startDirectMgmtProcess(endpoint)
	if err != nil {
		return err
	}
	return waitForOwnedMgmtListen(endpoint, func() (int, error) {
		if cmd.Process == nil {
			return 0, errors.New("management process has no pid")
		}
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return 0, err
		}
		return cmd.Process.Pid, nil
	})
}

func packagedMgmtUnitPresent() bool {
	for _, unitPath := range []string{
		"/lib/systemd/system/warptweet-mgmt.service",
		"/usr/lib/systemd/system/warptweet-mgmt.service",
	} {
		if _, err := os.Stat(unitPath); err == nil {
			_, lookErr := exec.LookPath("systemctl")
			return lookErr == nil
		}
	}
	return false
}

func startPackagedMgmtUnit() error {
	cmd := exec.Command("systemctl", "start", "warptweet-mgmt.service")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("start warptweet-mgmt.service: %w", err)
	}
	return nil
}

func packagedMgmtMainPID() (int, error) {
	cmd := exec.Command("systemctl", "show", "warptweet-mgmt.service", "--property=ActiveState", "--property=MainPID")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	active := false
	pid := 0
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			active = value == "active"
		case "MainPID":
			pid, _ = strconv.Atoi(value)
		}
	}
	if !active || pid <= 0 {
		return 0, errors.New("warptweet-mgmt.service is not active")
	}
	return pid, nil
}

func startDirectMgmtProcess(endpoint netip.AddrPort) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(serverStateDirectory, 0o700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(serverStateDirectory, "mgmt-listen.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, "server", "mgmt-listen", "--listen", endpoint.String())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = enrollListenSysProcAttr()
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	pidPath := filepath.Join(serverStateDirectory, "mgmt-listen.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		return nil, err
	}
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
	}()
	return cmd, nil
}

func waitForOwnedMgmtListen(endpoint netip.AddrPort, pidFn func() (int, error)) error {
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		pid, err := pidFn()
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if processOwnsTCPListen(pid, endpoint) {
			return nil
		}
		last = fmt.Errorf("pid %d does not own %s", pid, endpoint)
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("management RPC did not become ready on " + endpoint.String())
	}
	return last
}

func readPIDFile(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid pid file")
	}
	return pid, nil
}

func enrollListenAlreadyRunning(endpoint netip.AddrPort, enrollmentPin string) bool {
	return probeEnrollmentEndpoint(endpoint, enrollmentPin)
}

func probeEnrollmentEndpoint(endpoint netip.AddrPort, enrollmentPin string) bool {
	tlsConfig, err := enrollment.PinnedClientTLSConfig(enrollmentPin, time.Now)
	if err != nil {
		return false
	}
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: tlsConfig,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   200 * time.Millisecond,
		Transport: transport,
	}
	url := fmt.Sprintf("https://%s/v1/enroll", endpoint.String())
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusMethodNotAllowed
}

func parseHostTarget(value string) (netip.AddrPort, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.AddrPort{}, errors.New("target is required")
	}
	if !strings.Contains(value, ":") {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return netip.AddrPort{}, errors.New("port must be a nonzero TCP port")
		}
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), nil
	}
	return parseEndpoint(value)
}

func resolveHostListen(flagValue string) (netip.AddrPort, error) {
	if flagValue != "" {
		return parseEndpoint(flagValue)
	}
	if manifest, err := server.Load(installlayout.ServerManifestPath); err == nil {
		return netip.AddrPortFrom(manifest.Listen.Address, uint16(manifest.Listen.Port)), nil
	}
	candidates := nonLoopbackIPv4Addresses()
	switch len(candidates) {
	case 0:
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), defaultHostListenPort), nil
	case 1:
		return netip.AddrPortFrom(candidates[0], defaultHostListenPort), nil
	default:
		return netip.AddrPort{}, fmt.Errorf(
			"multiple non-loopback IPv4 addresses (%s); pass --listen explicitly",
			joinAddrs(candidates),
		)
	}
}

func nonLoopbackIPv4Addresses() []netip.Addr {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[netip.Addr]struct{}{}
	var candidates []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil {
				continue
			}
			parsed, ok := netip.AddrFromSlice(ip.To4())
			if !ok || !parsed.IsValid() || parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() {
				continue
			}
			if _, exists := seen[parsed]; exists {
				continue
			}
			seen[parsed] = struct{}{}
			candidates = append(candidates, parsed)
		}
	}
	return candidates
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, ", ")
}

func defaultHostLabel() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "host"
	}
	return host
}

const hostStateLockName = ".host.lock"

func withHostStateLock(fn func() error) error {
	err := enrollment.WithNonBlockingExclusiveLock(serverStateDirectory, hostStateLockName, fn)
	if errors.Is(err, enrollment.ErrBusy) {
		lockPath := filepath.Join(serverStateDirectory, hostStateLockName)
		return fmt.Errorf("%w: another host command holds %s", outcome.ErrHostBusy, lockPath)
	}
	return err
}

func refuseHostTargetChange(targetEndpoint netip.AddrPort) error {
	existing, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	current := netip.AddrPortFrom(existing.Target.Address, uint16(existing.Target.Port))
	if current == targetEndpoint {
		return nil
	}
	clients, err := enrollment.ListClients(installlayout.ClientsDirectory)
	if err != nil {
		return fmt.Errorf("list grants before target change: %w", err)
	}
	for _, record := range clients {
		if record.Status != enrollment.ClientStatusExpired && record.Status != enrollment.ClientStatusRevoked {
			return fmt.Errorf("host target cannot change from %s to %s while grant %s is %s", current, targetEndpoint, record.ClientID, record.Status)
		}
	}
	invites, err := enrollment.List(inviteDirectory)
	if err != nil {
		return fmt.Errorf("list invites before target change: %w", err)
	}
	for _, record := range invites {
		if record.Status == enrollment.StatusIssued {
			return fmt.Errorf("host target cannot change from %s to %s while invite %s is issued", current, targetEndpoint, record.InviteID)
		}
	}
	return nil
}

func ensureHostDirectories() error {
	if err := ensureDirectoryMode(filepath.Dir(installlayout.ServerHostKeyPath), 0o700); err != nil {
		return err
	}
	if err := ensureDirectoryMode(installlayout.AuthorizedKeysDirectory, 0o755); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Dir(installlayout.ServerManifestPath),
		filepath.Dir(inviteSecretPath),
	} {
		if err := ensureDirectoryMode(path, 0o755); err != nil {
			return err
		}
	}
	if err := ensureDirectoryMode(inviteDirectory, 0o700); err != nil {
		return err
	}
	if err := ensureDirectoryMode(installlayout.GrantSessionsDirectory, 0o770); err != nil {
		return err
	}
	if err := ensureDirectoryMode(installlayout.ClientsDirectory, 0o2750); err != nil {
		return err
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if err := os.Chown(installlayout.GrantSessionsDirectory, 0, installlayout.LinuxPrivsepGID); err != nil {
			return err
		}
		if err := os.Chown(installlayout.ClientsDirectory, 0, installlayout.LinuxPrivsepGID); err != nil {
			return err
		}
	}
	if err := ensureDirectoryMode(installlayout.ServerEnrollmentDirectory, 0o700); err != nil {
		return err
	}
	return ensureDirectoryMode(serverStateDirectory, 0o700)
}

func ensureDirectoryMode(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func ensureHostIdentity(ctx context.Context) (publicKey string, created bool, err error) {
	if _, err := os.Lstat(installlayout.ServerHostKeyPath); err == nil {
		key, derr := deriveHostPublicKey(ctx, installlayout.ServerHostKeyPath)
		return key, false, derr
	} else if !os.IsNotExist(err) {
		return "", false, err
	}

	keygen := installlayout.SSHKeygenPath
	if _, err := os.Stat(keygen); err != nil {
		return "", false, fmt.Errorf("bundled ssh-keygen is required at %s: %w", keygen, err)
	}
	cmd := exec.CommandContext(
		ctx,
		keygen,
		"-t", "mldsa44-ed25519",
		"-f", installlayout.ServerHostKeyPath,
		"-N", "",
		"-C", "warptweet-host",
	)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", false, fmt.Errorf("generate host key: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(installlayout.ServerHostKeyPath, 0o600); err != nil {
		return "", false, err
	}
	if err := os.Chown(installlayout.ServerHostKeyPath, 0, 0); err != nil && os.Geteuid() == 0 {
		return "", false, err
	}
	publicKey, err = deriveHostPublicKey(ctx, installlayout.ServerHostKeyPath)
	if err != nil {
		return "", false, err
	}
	if err := os.WriteFile(installlayout.ServerHostKeyPath+".pub", append([]byte(publicKey), '\n'), 0o644); err != nil {
		return "", false, err
	}
	return publicKey, true, nil
}

func ensureInviteSecret() error {
	if _, err := os.Lstat(inviteSecretPath); err == nil {
		_, readErr := enrollment.ReadSecret(inviteSecretPath)
		return readErr
	} else if !os.IsNotExist(err) {
		return err
	}
	secret, err := enrollment.GenerateSecret()
	if err != nil {
		return err
	}
	return enrollment.WriteSecret(inviteSecretPath, secret)
}

func writeHostManifest(listenEndpoint, targetEndpoint netip.AddrPort) (server.Config, error) {
	sshdDigest, err := fileSHA256(installlayout.SSHDPath)
	if err != nil {
		if existing, loadErr := server.Load(installlayout.ServerManifestPath); loadErr == nil &&
			existing.SSHDBinarySHA256 != "" && existing.SSHDBinarySHA256 != strings.Repeat("0", 64) {
			sshdDigest = existing.SSHDBinarySHA256
		} else {
			return server.Config{}, fmt.Errorf("hash sshd binary: %w", err)
		}
	}
	bundleDigest, err := fileSHA256(installlayout.OpenSSHBundleManifestPath)
	if err != nil {
		if existing, loadErr := server.Load(installlayout.ServerManifestPath); loadErr == nil &&
			existing.OpenSSHBundleManifestSHA256 != "" && existing.OpenSSHBundleManifestSHA256 != strings.Repeat("0", 64) {
			bundleDigest = existing.OpenSSHBundleManifestSHA256
		} else {
			return server.Config{}, fmt.Errorf("hash OpenSSH bundle manifest: %w", err)
		}
	}

	manifest := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            sshdDigest,
		OpenSSHBundleManifestSHA256: bundleDigest,
		Listen: server.Endpoint{
			Address: listenEndpoint.Addr(),
			Port:    server.Port(listenEndpoint.Port()),
		},
		Target: server.Endpoint{
			Address: targetEndpoint.Addr(),
			Port:    server.Port(targetEndpoint.Port()),
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: filepath.Join(installlayout.AuthorizedKeysDirectory, server.DefaultDedicatedUser),
	}
	if err := server.Validate(manifest); err != nil {
		return server.Config{}, err
	}
	if err := writeServerManifestAtomic(installlayout.ServerManifestPath, manifest); err != nil {
		return server.Config{}, err
	}
	if _, err := os.Lstat(manifest.AuthorizedKeysPath); os.IsNotExist(err) {
		if err := os.WriteFile(manifest.AuthorizedKeysPath, nil, 0o644); err != nil {
			return server.Config{}, err
		}
	}
	rendered, err := server.Render(manifest)
	if err != nil {
		return server.Config{}, err
	}
	if err := writeFileAtomic(installlayout.ServerConfigPath, rendered, 0o644); err != nil {
		return server.Config{}, fmt.Errorf("write restricted sshd configuration: %w", err)
	}
	return manifest, nil
}

func ensureSSHDStarted(ctx context.Context, manifest server.Config) (string, error) {
	endpoint := netip.AddrPortFrom(manifest.Listen.Address, uint16(manifest.Listen.Port))
	for _, unitPath := range []string{
		"/lib/systemd/system/warptweet-sshd.service",
		"/usr/lib/systemd/system/warptweet-sshd.service",
	} {
		if _, err := os.Stat(unitPath); err != nil {
			continue
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return "", errors.New("warptweet-sshd.service is installed but systemctl is unavailable")
		}
		enable := exec.CommandContext(ctx, "systemctl", "enable", "warptweet-hostsign.service", "warptweet-sshd.service")
		enable.Env = []string{"LANG=C", "LC_ALL=C"}
		if output, err := enable.CombinedOutput(); err != nil {
			return "", fmt.Errorf("enable warptweet-sshd.service: %w (%s)", err, strings.TrimSpace(string(output)))
		}
		cmd := exec.CommandContext(ctx, "systemctl", "start", "warptweet-sshd.service")
		cmd.Env = []string{"LANG=C", "LC_ALL=C"}
		if output, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("start warptweet-sshd.service: %w (%s)", err, strings.TrimSpace(string(output)))
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			active := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "warptweet-sshd.service")
			active.Env = []string{"LANG=C", "LC_ALL=C"}
			if active.Run() == nil && probeTCPListener(endpoint) {
				return "systemd_ready", nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return "", errors.New("warptweet-sshd.service did not become active and listening")
	}

	if probeTCPListener(endpoint) {
		return "", fmt.Errorf("listener %s is already occupied outside the packaged WarpTweet service", endpoint)
	}
	if err := os.MkdirAll(serverStateDirectory, 0o700); err != nil {
		return "", err
	}
	logPath := filepath.Join(serverStateDirectory, "dataplane.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(installlayout.ControllerPath, "server", "data-plane")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = enrollListenSysProcAttr()
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return "", err
	}
	pidPath := filepath.Join(serverStateDirectory, "dataplane.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_ = logFile.Close()
		return "", err
	}
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return "", fmt.Errorf("data plane exited before listening: %w", err)
		}
		if probeTCPListener(endpoint) {
			return "direct_ready", nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	return "", errors.New("data plane did not begin listening before the readiness deadline")
}

func probeTCPListener(endpoint netip.AddrPort) bool {
	connection, err := net.DialTimeout("tcp", endpoint.String(), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func mintServerInvite(
	ctx context.Context,
	clientName string,
	targetEndpoint netip.AddrPort,
	manifest server.Config,
	hostPublicKey string,
	enrollmentTLSSPKISHA256 string,
	authorizationSeconds int64,
) (enrollment.Invite, enrollment.Record, error) {
	if targetEndpoint.Addr().Compare(manifest.Target.Address) != 0 ||
		uint16(manifest.Target.Port) != targetEndpoint.Port() {
		return enrollment.Invite{}, enrollment.Record{}, fmt.Errorf(
			"invite target %s does not match server manifest target %s:%d",
			targetEndpoint,
			manifest.Target.Address,
			manifest.Target.Port,
		)
	}
	secret, err := enrollment.ReadSecret(inviteSecretPath)
	if err != nil {
		return enrollment.Invite{}, enrollment.Record{}, fmt.Errorf("read invite secret: %w", err)
	}
	if hostPublicKey == "" {
		hostPublicKey, err = deriveHostPublicKey(ctx, manifest.HostKeyPath)
		if err != nil {
			return enrollment.Invite{}, enrollment.Record{}, err
		}
	}
	selected, err := artifactprofile.Current()
	if err != nil {
		return enrollment.Invite{}, enrollment.Record{}, err
	}
	artifactID := string(selected.ID)
	return enrollment.Create(enrollment.CreateInput{
		ClientName:                   clientName,
		ServerAddress:                manifest.Listen.Address,
		ServerPort:                   uint16(manifest.Listen.Port),
		EnrollPort:                   enrollment.DefaultEnrollmentPort,
		TargetAddress:                manifest.Target.Address,
		TargetPort:                   uint16(manifest.Target.Port),
		Principal:                    manifest.DedicatedUser,
		ProfileID:                    manifest.ProfileID,
		ArtifactProfileID:            artifactID,
		HostPublicKey:                hostPublicKey,
		EnrollmentTLSSPKISHA256:      enrollmentTLSSPKISHA256,
		TTL:                          enrollment.DefaultTTL,
		AuthorizationDurationSeconds: authorizationSeconds,
		Secret:                       secret,
	})
}
