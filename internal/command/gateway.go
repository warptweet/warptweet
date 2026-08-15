package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const defaultGatewayListenPort uint16 = 2222

func runGateway(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("gateway", stderr)
	to := onceStringFlag{name: "--to"}
	name := onceStringFlag{name: "--name"}
	out := onceStringFlag{name: "--out"}
	listen := onceStringFlag{name: "--listen"}
	stdoutInvite := onceBoolFlag{name: "--stdout"}
	noInvite := onceBoolFlag{name: "--no-invite"}
	noEnrollListen := onceBoolFlag{name: "--no-enroll-listen"}
	asJSON := onceBoolFlag{name: "--json"}
	flags.Var(&to, "to", "target port or ip:port")
	flags.Var(&name, "name", "invite client label")
	flags.Var(&out, "out", "exact invite output path")
	flags.Var(&listen, "listen", "numeric server listen address:port")
	flags.Var(&stdoutInvite, "stdout", "print invite JSON only; do not write a file")
	flags.Var(&noInvite, "no-invite", "bootstrap gateway without minting an invite")
	flags.Var(&noEnrollListen, "no-enroll-listen", "do not start the enrollment HTTP listener")
	flags.Var(&asJSON, "json", "emit JSON")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if to.value == "" {
		return errors.New("gateway requires --to <port|ip:port>")
	}
	if stdoutInvite.value && noInvite.value {
		return errors.New("gateway --stdout cannot be combined with --no-invite")
	}
	if stdoutInvite.value && out.value != "" {
		return errors.New("gateway --stdout cannot be combined with --out")
	}
	if noInvite.value && (out.value != "" || name.value != "") {
		return errors.New("gateway --no-invite cannot be combined with invite naming flags")
	}

	targetEndpoint, err := parseGatewayTarget(to.value)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}
	listenEndpoint, err := resolveGatewayListen(listen.value)
	if err != nil {
		return err
	}

	if err := ensureGatewayDirectories(); err != nil {
		return err
	}
	hostPublicKey, createdHostKey, err := ensureHostIdentity(ctx)
	if err != nil {
		return err
	}
	if err := ensureInviteSecret(); err != nil {
		return err
	}
	manifest, err := writeGatewayManifest(listenEndpoint, targetEndpoint)
	if err != nil {
		return err
	}

	result := map[string]any{
		"status":         "ready",
		"target":         targetEndpoint.String(),
		"listen":         listenEndpoint.String(),
		"host_key_path":  installlayout.ServerHostKeyPath,
		"manifest_path":  installlayout.ServerManifestPath,
		"host_key":       map[string]any{"created": createdHostKey},
		"dedicated_user": manifest.DedicatedUser,
		"profile_id":     manifest.ProfileID,
	}
	fingerprint := sha256.Sum256([]byte(hostPublicKey))
	hostFingerprint := hex.EncodeToString(fingerprint[:])
	result["host_public_key_sha256"] = hostFingerprint

	if noInvite.value {
		enrollStatus := applyEnrollListenStatus(result, listenEndpoint.Addr(), noEnrollListen.value)
		if asJSON.value {
			return writeJSON(stdout, result)
		}
		return writeGatewayHuman(stdout, targetEndpoint.String(), listenEndpoint.String(), hostFingerprint, "", enrollStatus)
	}

	label := name.value
	if label == "" {
		label = defaultGatewayLabel()
	}
	label = enrollment.SanitizeInviteLabel(label)

	invite, record, err := mintServerInvite(ctx, label, targetEndpoint, manifest, hostPublicKey)
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
		if asJSON.value {
			var inviteObject any
			if err := json.Unmarshal(raw, &inviteObject); err != nil {
				return err
			}
			result["invite_id"] = invite.InviteID
			result["expires_at"] = invite.ExpiresAt
			result["invite"] = inviteObject
			return writeJSON(stdout, result)
		}
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
	result["expires_at"] = invite.ExpiresAt
	result["invite_path"] = invitePath
	result["client_name"] = label

	enrollStatus := applyEnrollListenStatus(result, listenEndpoint.Addr(), noEnrollListen.value)

	if asJSON.value {
		return writeJSON(stdout, result)
	}
	return writeGatewayHuman(stdout, targetEndpoint.String(), listenEndpoint.String(), hostFingerprint, invitePath, enrollStatus)
}

func applyEnrollListenStatus(result map[string]any, listenAddr netip.Addr, skip bool) string {
	enrollStatus := "skipped"
	if !skip {
		started, startErr := ensureEnrollListenStarted(listenAddr)
		if startErr != nil {
			result["enroll_listen_error"] = startErr.Error()
			enrollStatus = "error"
		} else if started {
			enrollStatus = "started"
		} else {
			enrollStatus = "already_running"
		}
	}
	result["enroll_listen"] = enrollStatus
	result["enroll_port"] = enrollment.DefaultEnrollmentPort
	return enrollStatus
}

func writeGatewayHuman(stdout io.Writer, target, listen, hostFingerprint, invitePath, enrollStatus string) error {
	_, err := fmt.Fprintf(stdout, "gateway ready\ntarget   %s\nlisten   %s\nhost     SHA256:%s\n", target, listen, hostFingerprint)
	if err != nil {
		return err
	}
	if invitePath != "" {
		_, err = fmt.Fprintf(stdout, "invite   %s\n", invitePath)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "enroll   :%d (%s)\n", enrollment.DefaultEnrollmentPort, enrollStatus)
	return err
}

func ensureEnrollListenStarted(listenAddr netip.Addr) (started bool, err error) {
	endpoint := netip.AddrPortFrom(listenAddr, enrollment.DefaultEnrollmentPort)
	pidPath := filepath.Join(serverStateDirectory, "enroll-listen.pid")
	if enrollListenAlreadyRunning(endpoint, pidPath) {
		return false, nil
	}

	// Prefer the packaged unit when present so confinement matches production.
	if tryStartEnrollUnit(endpoint) {
		return true, nil
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
			_ = logFile.Close()
			return false, fmt.Errorf("enroll-listen exited before accepting: %w", err)
		}
		if probeEnrollmentEndpoint(endpoint) {
			return true, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Still running but not accepting yet: report starting, not error.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return false, fmt.Errorf("enroll-listen exited before accepting: %w", err)
	}
	return true, nil
}

func tryStartEnrollUnit(endpoint netip.AddrPort) bool {
	unitPath := "/lib/systemd/system/warptweet-enroll.service"
	if _, err := os.Stat(unitPath); err != nil {
		unitPath = "/usr/lib/systemd/system/warptweet-enroll.service"
		if _, err := os.Stat(unitPath); err != nil {
			return false
		}
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	cmd := exec.Command("systemctl", "start", "warptweet-enroll.service")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := cmd.Run(); err != nil {
		return false
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if probeEnrollmentEndpoint(endpoint) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Unit started but endpoint not yet probing: still count as started so gateway
	// does not also spawn a detached listener that fights the unit for the port.
	return true
}

func enrollListenAlreadyRunning(endpoint netip.AddrPort, pidPath string) bool {
	// Require an enrollment-shaped HTTP response; plain TCP accept is not enough.
	if !probeEnrollmentEndpoint(endpoint) {
		return false
	}
	// Prefer a live recorded pid when present; stale/missing pid still counts as
	// already-running when the enrollment endpoint answers.
	if raw, err := os.ReadFile(pidPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
			if process, err := os.FindProcess(pid); err == nil {
				_ = process.Signal(syscall.Signal(0))
			}
		}
	}
	return true
}

func probeEnrollmentEndpoint(endpoint netip.AddrPort) bool {
	client := &http.Client{Timeout: 200 * time.Millisecond}
	url := fmt.Sprintf("http://%s/v1/enroll", endpoint.String())
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	// Enrollment handler answers POST; connection refused / non-HTTP peers fail above.
	return resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusMethodNotAllowed
}

func parseGatewayTarget(value string) (netip.AddrPort, error) {
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

func resolveGatewayListen(flagValue string) (netip.AddrPort, error) {
	if flagValue != "" {
		return parseEndpoint(flagValue)
	}
	if manifest, err := server.Load(installlayout.ServerManifestPath); err == nil {
		return netip.AddrPortFrom(manifest.Listen.Address, uint16(manifest.Listen.Port)), nil
	}
	candidates := nonLoopbackIPv4Addresses()
	switch len(candidates) {
	case 0:
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), defaultGatewayListenPort), nil
	case 1:
		return netip.AddrPortFrom(candidates[0], defaultGatewayListenPort), nil
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

func defaultGatewayLabel() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "host"
	}
	return host
}

func ensureGatewayDirectories() error {
	for _, path := range []string{
		filepath.Dir(installlayout.ServerHostKeyPath),
		installlayout.AuthorizedKeysDirectory,
		filepath.Dir(installlayout.ServerManifestPath),
		filepath.Dir(inviteSecretPath),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(inviteDirectory, 0o700); err != nil {
		return err
	}
	return os.MkdirAll(serverStateDirectory, 0o700)
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

func writeGatewayManifest(listenEndpoint, targetEndpoint netip.AddrPort) (server.Config, error) {
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
		if err := os.WriteFile(manifest.AuthorizedKeysPath, nil, 0o600); err != nil {
			return server.Config{}, err
		}
	}
	return manifest, nil
}

func mintServerInvite(
	ctx context.Context,
	clientName string,
	targetEndpoint netip.AddrPort,
	manifest server.Config,
	hostPublicKey string,
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
		ClientName:        clientName,
		ServerAddress:     manifest.Listen.Address,
		ServerPort:        uint16(manifest.Listen.Port),
		EnrollPort:        enrollment.DefaultEnrollmentPort,
		TargetAddress:     manifest.Target.Address,
		TargetPort:        uint16(manifest.Target.Port),
		Principal:         manifest.DedicatedUser,
		ProfileID:         manifest.ProfileID,
		ArtifactProfileID: artifactID,
		HostPublicKey:     hostPublicKey,
		TTL:               enrollment.DefaultTTL,
		Secret:            secret,
	})
}
