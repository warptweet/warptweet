package command

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/lifecycle"
	"warptweet.com/warptweet/internal/profile"
)

func runEnroll(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("enroll", stderr)
	yes := onceBoolFlag{name: "--yes"}
	prepareOnly := onceBoolFlag{name: "--prepare-only"}
	listenPort := onceStringFlag{name: "--listen-port"}
	proofPath := onceStringFlag{name: "--proof"}
	flags.Var(&yes, "yes", "skip interactive confirmation")
	flags.Var(&prepareOnly, "prepare-only", "stage local generation without activating production state")
	flags.Var(&listenPort, "listen-port", "loopback listen port (default 15432)")
	flags.Var(&proofPath, "proof", "path to server enrollment proof JSON")
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("enroll requires exactly one invite path or JSON operand")
	}

	raw, err := readInviteInput(positionals[0])
	if err != nil {
		return err
	}
	invite, view, err := enrollment.ParseClientInvite(raw, time.Now().UTC())
	if err != nil {
		return err
	}
	if listenPort.value != "" {
		port, err := strconv.ParseUint(listenPort.value, 10, 16)
		if err != nil || port == 0 {
			return errors.New("listen-port must be a nonzero TCP port")
		}
		view.ListenPort = uint16(port)
	}

	if !yes.value {
		fmt.Fprintf(stderr, "WarpTweet enrollment request\n")
		fmt.Fprintf(stderr, "  invite:     %s\n", view.InviteID)
		fmt.Fprintf(stderr, "  server:     %s:%d\n", view.ServerAddress, view.ServerPort)
		fmt.Fprintf(stderr, "  target:     %s:%d\n", view.TargetAddress, view.TargetPort)
		fmt.Fprintf(stderr, "  principal:  %s\n", view.Principal)
		fmt.Fprintf(stderr, "  profile:    %s\n", view.ProfileID)
		fmt.Fprintf(stderr, "  local bind: %s:%d\n", view.ListenAddress, view.ListenPort)
		fmt.Fprintf(stderr, "  host key:   %s\n", truncateMiddle(view.HostPublicKey, 72))
		fmt.Fprintf(stderr, "Type ENROLL to continue: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) != "ENROLL" {
			return errors.New("enrollment aborted")
		}
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	keygen := keygenPath(layout)

	generationID := time.Now().UTC().Format("20060102T150405Z")
	stageRoot := filepath.Join(os.TempDir(), "warptweet-enroll-"+generationID)
	if err := os.MkdirAll(stageRoot, 0o700); err != nil {
		return err
	}
	// Keep stage for prepare-only; otherwise clean up after activation.
	cleanupStage := !prepareOnly.value
	if cleanupStage {
		defer func() { _ = os.RemoveAll(stageRoot) }()
	}

	identityPath := filepath.Join(stageRoot, "client")
	cmd := exec.CommandContext(ctx, keygen,
		"-t", "mldsa44-ed25519",
		"-f", identityPath,
		"-N", "",
		"-C", "warptweet-client-"+view.TunnelID,
	)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("generate client key: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	publicKeyBytes, err := os.ReadFile(identityPath + ".pub")
	if err != nil {
		return err
	}
	publicKey := strings.TrimSpace(string(publicKeyBytes))
	if publicKey == "" || strings.ContainsAny(publicKey, "\r\n") {
		return errors.New("client public key must be one line")
	}

	request := enrollment.EnrollmentRequest{
		InviteID:      invite.InviteID,
		Nonce:         invite.Nonce,
		ClientName:    invite.ClientName,
		PublicKey:     publicKey,
		ProfileID:     invite.ProfileID,
		TunnelID:      view.TunnelID,
		ListenAddress: view.ListenAddress,
		ListenPort:    view.ListenPort,
	}
	requestJSON, err := enrollment.EncodeEnrollmentRequest(request)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageRoot, "enrollment-request.json"), append(requestJSON, '\n'), 0o600); err != nil {
		return err
	}

	var proof enrollment.EnrollmentProof
	if proofPath.value != "" {
		proofRaw, err := os.ReadFile(proofPath.value)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(proofRaw, &proof); err != nil {
			return fmt.Errorf("parse enrollment proof: %w", err)
		}
		if err := enrollment.ValidateEnrollmentProof(proof, invite, publicKey); err != nil {
			return err
		}
	} else if !prepareOnly.value {
		return errors.New("enroll requires --proof <server-proof.json> or --prepare-only until the enrollment endpoint is packaged")
	}

	sshDigest := strings.Repeat("0", 64)
	if digest, err := fileSHA256(layout.SSHPath); err == nil {
		sshDigest = digest
	} else if digest, err := fileSHA256(installlayout.SSHPath); err == nil {
		sshDigest = digest
	}
	manifest, err := enrollment.BuildClientManifest(invite, view.TunnelID, view.ListenPort, sshDigest)
	if err != nil {
		return err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	manifestStage := filepath.Join(stageRoot, "client.wt")
	if err := os.WriteFile(manifestStage, append(manifestJSON, '\n'), 0o600); err != nil {
		return err
	}

	hostPin, err := knownhosts.RenderManagedHost(view.TunnelID, []byte(invite.HostPublicKey+"\n"))
	if err != nil {
		hostPin = []byte(fmt.Sprintf("warptweet-%s %s\n", view.TunnelID, invite.HostPublicKey))
	}
	knownHostsStage := filepath.Join(stageRoot, "known_hosts")
	if err := os.WriteFile(knownHostsStage, hostPin, 0o600); err != nil {
		return err
	}
	emptyTrust := filepath.Join(stageRoot, "known_hosts.empty")
	if err := os.WriteFile(emptyTrust, nil, 0o600); err != nil {
		return err
	}

	if prepareOnly.value {
		return writeJSON(stdout, map[string]any{
			"status":              "prepared",
			"tunnel_id":           view.TunnelID,
			"listen_endpoint":     fmt.Sprintf("%s:%d", view.ListenAddress, view.ListenPort),
			"enrollment_request":  request,
			"stage_directory":     stageRoot,
			"identity_public_key": publicKey,
			"profile_id":          profile.CurrentID,
			"target_health":       lifecycle.TargetHealthNotChecked,
		})
	}

	if err := activateGeneration(
		layout.ClientManifestPath,
		layout.ClientIdentityPath,
		layout.ClientKnownHostsPath,
		layout.ClientGlobalKnownHostsPath,
		identityPath,
		manifestStage,
		knownHostsStage,
		emptyTrust,
	); err != nil {
		return err
	}

	receiptDir := filepath.Join(filepath.Dir(layout.ClientManifestPath), "enrollment")
	_ = os.MkdirAll(receiptDir, 0o700)
	receipt := map[string]any{
		"invite_id":   invite.InviteID,
		"client_id":   proof.ClientID,
		"tunnel_id":   view.TunnelID,
		"accepted_at": proof.AcceptedAt,
		"generation":  generationID,
	}
	receiptJSON, _ := json.Marshal(receipt)
	_ = os.WriteFile(filepath.Join(receiptDir, invite.InviteID+".json"), append(receiptJSON, '\n'), 0o600)

	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	_ = store.Write(lifecycle.State{
		TunnelID:       view.TunnelID,
		Phase:          lifecycle.PhaseStopped,
		ListenEndpoint: fmt.Sprintf("%s:%d", view.ListenAddress, view.ListenPort),
		TargetHealth:   lifecycle.TargetHealthNotChecked,
		Generation:     generationID,
	})

	return writeJSON(stdout, map[string]any{
		"status":          "enrolled",
		"tunnel_id":       view.TunnelID,
		"client_id":       proof.ClientID,
		"listen_endpoint": fmt.Sprintf("%s:%d", view.ListenAddress, view.ListenPort),
		"generation":      generationID,
		"target_health":   lifecycle.TargetHealthNotChecked,
		"next":            "warptweet up " + view.TunnelID,
	})
}

func runUp(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	flags := newFlagSet("up", stderr)
	once := onceBoolFlag{name: "--once"}
	flags.Var(&once, "once", "do not restart after exit")
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("up requires exactly one tunnel-id")
	}
	tunnelID := positionals[0]
	if dependencies.loadProductionClientManifest == nil {
		return errors.New("production client manifest loader is required")
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	lock, err := store.Lock(tunnelID)
	if err != nil {
		return err
	}
	defer lifecycle.Unlock(lock)

	current, err := store.Read(tunnelID)
	if err != nil {
		return err
	}
	if current.Phase == lifecycle.PhaseReady && current.PID > 0 && processAlive(current.PID) {
		return writeJSON(stdout, map[string]any{
			"status":          "already_ready",
			"tunnel_id":       tunnelID,
			"phase":           current.Phase,
			"pid":             current.PID,
			"listen_endpoint": current.ListenEndpoint,
			"target_health":   lifecycle.TargetHealthNotChecked,
		})
	}

	_ = store.Write(lifecycle.State{
		TunnelID:     tunnelID,
		Phase:        lifecycle.PhasePreparing,
		TargetHealth: lifecycle.TargetHealthNotChecked,
	})

	manifest, err := dependencies.loadProductionClientManifest(layout.ClientManifestPath)
	if err != nil {
		_ = store.Write(lifecycle.State{TunnelID: tunnelID, Phase: lifecycle.PhaseFailed, Error: err.Error(), TargetHealth: lifecycle.TargetHealthNotChecked})
		return err
	}
	spec, err := clientSpec(manifest, tunnelID)
	if err != nil {
		_ = store.Write(lifecycle.State{TunnelID: tunnelID, Phase: lifecycle.PhaseFailed, Error: err.Error(), TargetHealth: lifecycle.TargetHealthNotChecked})
		return err
	}
	listenEndpoint := fmt.Sprintf("%s:%d", spec.ListenAddress, spec.ListenPort)

	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"run", "--config", layout.ClientManifestPath, "--tunnel", tunnelID}
	if once.value || !once.set {
		// Default to --once for up so package/service managers own restart policy.
		args = append(args, "--once")
	}
	cmd := exec.CommandContext(ctx, self, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := cmd.Start(); err != nil {
		_ = store.Write(lifecycle.State{TunnelID: tunnelID, Phase: lifecycle.PhaseFailed, Error: err.Error(), TargetHealth: lifecycle.TargetHealthNotChecked})
		return err
	}
	_ = store.Write(lifecycle.State{
		TunnelID:       tunnelID,
		Phase:          lifecycle.PhaseAwaitingReadiness,
		PID:            cmd.Process.Pid,
		ListenEndpoint: listenEndpoint,
		TargetHealth:   lifecycle.TargetHealthNotChecked,
	})

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		phase := lifecycle.PhaseFailed
		message := "process exited before ready"
		if err == nil {
			phase = lifecycle.PhaseStopped
			message = ""
		} else {
			message = err.Error()
		}
		_ = store.Write(lifecycle.State{
			TunnelID:       tunnelID,
			Phase:          phase,
			ListenEndpoint: listenEndpoint,
			TargetHealth:   lifecycle.TargetHealthNotChecked,
			Error:          message,
		})
		if err != nil {
			return fmt.Errorf("tunnel exited: %w", err)
		}
	case <-timer.C:
		_ = store.Write(lifecycle.State{
			TunnelID:       tunnelID,
			Phase:          lifecycle.PhaseReady,
			PID:            cmd.Process.Pid,
			ListenEndpoint: listenEndpoint,
			TargetHealth:   lifecycle.TargetHealthNotChecked,
		})
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM)
		return ctx.Err()
	}

	return writeJSON(stdout, map[string]any{
		"status":          "started",
		"tunnel_id":       tunnelID,
		"phase":           lifecycle.PhaseReady,
		"pid":             cmd.Process.Pid,
		"listen_endpoint": listenEndpoint,
		"target_health":   lifecycle.TargetHealthNotChecked,
	})
}

func runStatus(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("status", stderr)
	asJSON := onceBoolFlag{name: "--json"}
	flags.Var(&asJSON, "json", "emit JSON")
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	useJSON := true
	if asJSON.set {
		useJSON = asJSON.value
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	if len(positionals) > 1 {
		return errors.New("status accepts at most one tunnel-id")
	}
	if len(positionals) == 1 {
		state, err := store.Read(positionals[0])
		if err != nil {
			return err
		}
		if useJSON {
			return writeJSON(stdout, state)
		}
		fmt.Fprintf(stdout, "%s %s listen=%s target_health=%s pid=%d\n",
			state.TunnelID, state.Phase, state.ListenEndpoint, state.TargetHealth, state.PID)
		return nil
	}
	states, err := store.List()
	if err != nil {
		return err
	}
	if useJSON {
		return writeJSON(stdout, map[string]any{"tunnels": states})
	}
	for _, state := range states {
		fmt.Fprintf(stdout, "%s %s listen=%s target_health=%s pid=%d\n",
			state.TunnelID, state.Phase, state.ListenEndpoint, state.TargetHealth, state.PID)
	}
	return nil
}

func runDown(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("down", stderr)
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("down requires exactly one tunnel-id")
	}
	tunnelID := positionals[0]
	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	lock, err := store.Lock(tunnelID)
	if err != nil {
		return err
	}
	defer lifecycle.Unlock(lock)

	state, err := store.Read(tunnelID)
	if err != nil {
		return err
	}
	_ = store.Write(lifecycle.State{
		TunnelID:       tunnelID,
		Phase:          lifecycle.PhaseStopping,
		PID:            state.PID,
		ListenEndpoint: state.ListenEndpoint,
		TargetHealth:   lifecycle.TargetHealthNotChecked,
		Generation:     state.Generation,
	})
	if state.PID > 0 {
		_ = store.Signal(tunnelID, syscall.SIGTERM)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if !processAlive(state.PID) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if processAlive(state.PID) {
			_ = store.Signal(tunnelID, syscall.SIGKILL)
		}
	}
	_ = store.Write(lifecycle.State{
		TunnelID:       tunnelID,
		Phase:          lifecycle.PhaseStopped,
		ListenEndpoint: state.ListenEndpoint,
		TargetHealth:   lifecycle.TargetHealthNotChecked,
		Generation:     state.Generation,
	})
	return writeJSON(stdout, map[string]any{
		"status":        "stopped",
		"tunnel_id":     tunnelID,
		"phase":         lifecycle.PhaseStopped,
		"target_health": lifecycle.TargetHealthNotChecked,
		"identity":      "preserved",
	})
}

func runRotate(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("rotate", stderr)
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("rotate requires exactly one tunnel-id")
	}
	return writeJSON(stdout, map[string]any{
		"status":        "unsupported",
		"tunnel_id":     positionals[0],
		"error":         "client key rotation requires a live enrollment endpoint and provisioner activate-generation RPC",
		"target_health": lifecycle.TargetHealthNotChecked,
	})
}

func runRevokeTunnel(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("revoke", stderr)
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("revoke requires exactly one tunnel-id")
	}
	return writeJSON(stdout, map[string]any{
		"status":        "unsupported",
		"tunnel_id":     positionals[0],
		"error":         "client revoke requires durable gateway acknowledgment before local completion",
		"target_health": lifecycle.TargetHealthNotChecked,
	})
}

func runUninstall(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("uninstall", stderr)
	preserve := onceBoolFlag{name: "--preserve-identity"}
	flags.Var(&preserve, "preserve-identity", "keep identity and trust material")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if !preserve.value {
		return errors.New("uninstall requires --preserve-identity (destroying identity is an explicit package uninstall path)")
	}
	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	states, _ := store.List()
	for _, state := range states {
		if state.PID > 0 {
			_ = store.Signal(state.TunnelID, syscall.SIGTERM)
		}
		_ = store.Write(lifecycle.State{
			TunnelID:       state.TunnelID,
			Phase:          lifecycle.PhaseStopped,
			ListenEndpoint: state.ListenEndpoint,
			TargetHealth:   lifecycle.TargetHealthNotChecked,
			Generation:     state.Generation,
		})
	}
	return writeJSON(stdout, map[string]any{
		"status":   "stopped_local_tunnels",
		"identity": "preserved",
		"note":     "package removal remains a platform package manager concern",
	})
}

func activateGeneration(
	manifestPath string,
	identityPath string,
	knownHostsPath string,
	emptyTrustPath string,
	stageIdentity string,
	stageManifest string,
	stageKnownHosts string,
	stageEmpty string,
) error {
	for _, dir := range []string{
		filepath.Dir(manifestPath),
		filepath.Dir(identityPath),
		filepath.Dir(knownHostsPath),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := copyFile(stageIdentity, identityPath, 0o440); err != nil {
		return err
	}
	if err := copyFile(stageIdentity+".pub", identityPath+".pub", 0o440); err != nil {
		return err
	}
	if err := copyFile(stageManifest, manifestPath, 0o440); err != nil {
		return err
	}
	if err := copyFile(stageKnownHosts, knownHostsPath, 0o440); err != nil {
		return err
	}
	return copyFile(stageEmpty, emptyTrustPath, 0o440)
}

func copyFile(source, destination string, mode os.FileMode) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeFileAtomic(destination, contents, mode)
}

func keygenPath(layout artifactprofile.Layout) string {
	if layout.SSHKeygenPath != "" {
		if _, err := os.Stat(layout.SSHKeygenPath); err == nil {
			return layout.SSHKeygenPath
		}
	}
	if layout.SSHPath != "" {
		candidate := filepath.Join(filepath.Dir(layout.SSHPath), "ssh-keygen")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return installlayout.SSHKeygenPath
}

func readInviteInput(value string) ([]byte, error) {
	if strings.HasPrefix(strings.TrimSpace(value), "{") {
		return []byte(value), nil
	}
	return os.ReadFile(value)
}

func truncateMiddle(value string, max int) string {
	if len(value) <= max {
		return value
	}
	keep := (max - 3) / 2
	return value[:keep] + "..." + value[len(value)-keep:]
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}
