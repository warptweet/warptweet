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
	"warptweet.com/warptweet/internal/inspectnet"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/server"
)

const defaultHostListenPort uint16 = 2222

// errHostRequiresLinux is the public host fail-closed error on non-Linux GOOS.
var errHostRequiresLinux = errors.New("WarpTweet host requires Linux; this is the server command")

func runHost(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("host", stderr)
	to := onceStringFlag{name: "--to"}
	name := onceStringFlag{name: "--name"}
	out := onceStringFlag{name: "--out"}
	listen := onceStringFlag{name: "--listen"}
	listenInterface := onceStringFlag{name: "--listen-interface"}
	advertise := onceStringFlag{name: "--advertise"}
	enrollListen := onceStringFlag{name: "--enroll-listen"}
	enrollAdvertise := onceStringFlag{name: "--enroll-advertise"}
	stdoutInvite := onceBoolFlag{name: "--stdout"}
	noInvite := onceBoolFlag{name: "--no-invite"}
	asJSON := onceBoolFlag{name: "--json"}
	accessFor := onceStringFlag{name: "--access-for"}
	flags.Var(&to, "to", "target port or ip:port")
	flags.Var(&name, "name", "invite client label")
	flags.Var(&out, "out", "exact invite output path")
	flags.Var(&listen, "listen", "numeric server listen address:port")
	flags.Var(&listenInterface, "listen-interface", "Linux interface name resolved to a concrete bind address")
	flags.Var(&advertise, "advertise", "published data dial host:port")
	flags.Var(&enrollListen, "enroll-listen", "enrollment bind address:port")
	flags.Var(&enrollAdvertise, "enroll-advertise", "published enrollment dial host:port")
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
	if runtime.GOOS != "linux" {
		return errHostRequiresLinux
	}
	if err := ensureHostDirectories(); err != nil {
		return err
	}
	label := name.value
	if label == "" {
		label = defaultHostLabel()
	}
	label = enrollment.SanitizeInviteLabel(label)

	var (
		applied    hostApplyResult
		invitePath string
	)
	if err := withHostOperationLock(func() error {
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
		env := productionHostApplyEnv()
		result, err := applyHostConfiguration(ctx, env, hostApplyInput{
			Target: targetEndpoint,
			Flags: hostPublicationFlags{
				Listen:          listen,
				ListenInterface: listenInterface,
				Advertise:       advertise,
				EnrollListen:    enrollListen,
				EnrollAdvertise: enrollAdvertise,
			},
			NoInvite:             noInvite.value,
			Label:                label,
			AuthorizationSeconds: authorizationSeconds,
		})
		if err != nil {
			return err
		}
		applied = result
		if err := reconcileExpiredGrants(result.Manifest, time.Now().UTC()); err != nil {
			return fmt.Errorf("reconcile expired grants: %w", err)
		}
		if err := reconcileManagedAuthorizations(result.Manifest); err != nil {
			return fmt.Errorf("reconcile managed authorizations: %w", err)
		}
		if err := ensureMgmtListenStarted(); err != nil {
			return err
		}
		if noInvite.value {
			return nil
		}
		raw := result.InviteBlob
		if stdoutInvite.value {
			return nil
		}
		if out.value != "" {
			invitePath, err = enrollment.WriteInviteFileExact(out.value, raw)
		} else {
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return cwdErr
			}
			invitePath, err = enrollment.WriteInviteFile(cwd, label, result.Invite.InviteID, raw)
		}
		return err
	}); err != nil {
		return err
	}

	if stdoutInvite.value && !noInvite.value {
		_, err := stdout.Write(applied.InviteBlob)
		return err
	}

	dataDial, _ := applied.Publication.DataDial.Host.Canonical()
	enrollDial, _ := applied.Publication.EnrollDial.Host.Canonical()
	result := map[string]any{
		"local_listener_ready":             true,
		"published_endpoint_configured":    true,
		"external_reachability_unverified": true,
		"target":                           targetEndpoint.String(),
		"listen":                           applied.Publication.DataListen.AddrPort().String(),
		"data_dial":                        fmt.Sprintf("%s:%d", dataDial, applied.Publication.DataDial.Port),
		"enrollment_listen":                applied.Publication.EnrollListen.AddrPort().String(),
		"enrollment_dial":                  fmt.Sprintf("%s:%d", enrollDial, applied.Publication.EnrollDial.Port),
		"published_endpoint_generation":    applied.Manifest.Network.PublishedEndpointGeneration,
		"host_key_path":                    installlayout.ServerHostKeyPath,
		"manifest_path":                    installlayout.ServerManifestPath,
		"host_key":                         map[string]any{"created": applied.CreatedHostKey},
		"enrollment_tls": map[string]any{
			"created":     applied.CreatedEnrollmentIdentity,
			"renewed":     applied.RenewedEnrollmentCertificate,
			"spki_sha256": applied.EnrollmentPin,
		},
		"dedicated_user": applied.Manifest.DedicatedUser,
		"profile_id":     applied.Manifest.ProfileID,
		"data_plane":     applied.DataPlaneStatus,
		"enroll_listen":  applied.EnrollStatus,
		"enroll_port":    applied.Publication.EnrollListen.Port,
	}
	fingerprint := sha256.Sum256([]byte(applied.HostPublicKey))
	hostFingerprint := hex.EncodeToString(fingerprint[:])
	result["host_public_key_sha256"] = hostFingerprint

	if !noInvite.value {
		result["invite_id"] = applied.Invite.InviteID
		result["invite_expires_at"] = applied.Invite.ExpiresAt
		result["authorization_duration_seconds"] = applied.Invite.AuthorizationDurationSeconds
		result["invite_path"] = invitePath
		result["invite_class"] = "confidential_bearer"
		result["client_name"] = label
		if applied.ResumedInvite {
			result["invite_resumed"] = true
		}
	}

	if asJSON.value {
		return writeJSON(stdout, result)
	}
	return writeHostHuman(stdout, hostHumanOutput{
		Target:               targetEndpoint.String(),
		Listen:               applied.Publication.DataListen.AddrPort().String(),
		DataDial:             fmt.Sprintf("%s:%d", dataDial, applied.Publication.DataDial.Port),
		EnrollmentDial:       fmt.Sprintf("%s:%d", enrollDial, applied.Publication.EnrollDial.Port),
		Fingerprint:          hostFingerprint,
		InvitePath:           invitePath,
		InviteExpiresAt:      applied.Invite.ExpiresAt,
		AuthorizationSeconds: applied.Invite.AuthorizationDurationSeconds,
		EnrollStatus:         applied.EnrollStatus,
		EnrollPort:           applied.Publication.EnrollListen.Port,
	})
}

type hostHumanOutput struct {
	Target               string
	Listen               string
	DataDial             string
	EnrollmentDial       string
	Fingerprint          string
	InvitePath           string
	InviteExpiresAt      string
	AuthorizationSeconds int64
	EnrollStatus         string
	EnrollPort           uint16
}

func writeHostHuman(stdout io.Writer, output hostHumanOutput) error {
	_, err := fmt.Fprintf(stdout, "local_listener_ready\npublished_endpoint_configured\nexternal_reachability_unverified\ntarget   %s\nlisten   %s\n", output.Target, output.Listen)
	if err != nil {
		return err
	}
	if output.DataDial != "" {
		_, err = fmt.Fprintf(stdout, "data dial   %s\n", output.DataDial)
		if err != nil {
			return err
		}
	}
	if output.EnrollmentDial != "" {
		_, err = fmt.Fprintf(stdout, "enrollment dial   %s\n", output.EnrollmentDial)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "host     SHA256:%s\n", output.Fingerprint)
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
	port := output.EnrollPort
	if port == 0 {
		port = enrollment.DefaultEnrollmentPort
	}
	_, err = fmt.Fprintf(stdout, "enroll   :%d (%s)\n", port, output.EnrollStatus)
	return err
}

func ensureEnrollListenStarted(endpoint netip.AddrPort, enrollmentPin string, restart bool) (started bool, err error) {
	pidPath := filepath.Join(serverStateDirectory, "enroll-listen.pid")
	if !restart && enrollListenAlreadyRunning(endpoint, enrollmentPin) {
		return false, nil
	}
	if restart {
		_ = stopEnrollListen(pidPath)
	}

	// Prefer the packaged unit when present so confinement matches production.
	if handled, unitErr := tryStartEnrollUnit(endpoint, enrollmentPin, restart); handled {
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

func stopEnrollListen(pidPath string) error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.Command("systemctl", "stop", "warptweet-enroll.service")
		cmd.Env = []string{"LANG=C", "LC_ALL=C"}
		_ = cmd.Run()
	}
	pid, err := readPIDFile(pidPath)
	if err != nil {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	_ = proc.Signal(syscall.SIGTERM)
	_ = os.Remove(pidPath)
	return nil
}

func tryStartEnrollUnit(endpoint netip.AddrPort, enrollmentPin string, restart bool) (bool, error) {
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
	action := "start"
	if restart {
		action = "restart"
	}
	cmd := exec.Command("systemctl", action, "warptweet-enroll.service")
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

func discoverHostBind() (netip.Addr, error) {
	ifaces, err := inspectnet.ListHostInterfaces()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("inspect-network: list interfaces: %w; pass --listen", err)
	}
	addr, err := inspectnet.Discover(inspectnet.KernelRouteLookup, ifaces)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func resolveListen(flagValue string, stored *server.Config, discover func() (netip.Addr, error)) (netip.AddrPort, error) {
	if flagValue != "" {
		return parseEndpoint(flagValue)
	}
	if stored != nil {
		return stored.Network.Data.Listen.AddrPort(), nil
	}
	addr, err := discover()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !addr.IsValid() {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), defaultHostListenPort), nil
	}
	return netip.AddrPortFrom(addr, defaultHostListenPort), nil
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

func publicationChangeBlocked(clients []enrollment.ClientRecord, invites []enrollment.Record) error {
	for _, record := range clients {
		if record.Status != enrollment.ClientStatusExpired && record.Status != enrollment.ClientStatusRevoked {
			return fmt.Errorf("published endpoints cannot change while grant %s is %s", record.ClientID, record.Status)
		}
	}
	for _, record := range invites {
		if record.Status == enrollment.StatusIssued {
			return fmt.Errorf("published endpoints cannot change while invite %s is issued", record.InviteID)
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
	// 0o2750 is not setgid in Go's FileMode. os.ModeSetgid|0o750 is.
	// warptweet host has full privileges and must restore the bit so
	// capability-bounded writers inherit group warptweet-sshd.
	if err := ensureDirectoryMode(installlayout.ClientsDirectory, os.ModeSetgid|0o750); err != nil {
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

func ensureSSHDStarted(ctx context.Context, endpoint netip.AddrPort, restart bool) (string, error) {
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
		action := "start"
		if restart {
			action = "restart"
		}
		cmd := exec.CommandContext(ctx, "systemctl", action, "warptweet-sshd.service")
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
	if hostPublicKey == "" {
		var err error
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
	dataHost, err := manifest.Network.Data.Dial.Host.Canonical()
	if err != nil {
		return enrollment.Invite{}, enrollment.Record{}, err
	}
	enrollHost, err := manifest.Network.Enrollment.Dial.Host.Canonical()
	if err != nil {
		return enrollment.Invite{}, enrollment.Record{}, err
	}
	enrollPort := manifest.Network.Enrollment.Dial.Port
	if enrollPort == 0 {
		enrollPort = enrollment.DefaultEnrollmentPort
	}
	return enrollment.Create(enrollment.CreateInput{
		ClientName:                   clientName,
		DataHost:                     dataHost,
		DataPort:                     manifest.Network.Data.Dial.Port,
		EnrollmentHost:               enrollHost,
		EnrollmentPort:               enrollPort,
		EnrollmentTLSSPKISHA256:      enrollmentTLSSPKISHA256,
		PublishedEndpointGeneration:  manifest.Network.PublishedEndpointGeneration,
		TargetAddress:                manifest.Target.Address,
		TargetPort:                   uint16(manifest.Target.Port),
		Principal:                    manifest.DedicatedUser,
		ProfileID:                    manifest.ProfileID,
		ArtifactProfileID:            artifactID,
		HostPublicKey:                hostPublicKey,
		TTL:                          enrollment.DefaultTTL,
		AuthorizationDurationSeconds: authorizationSeconds,
	})
}
