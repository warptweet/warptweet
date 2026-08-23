package command

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/lifecycle"
	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/provisioner"
	"warptweet.com/warptweet/internal/routestate"
)

func runEnroll(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("enroll", stderr)
	yes := onceBoolFlag{name: "--yes"}
	prepareOnly := onceBoolFlag{name: "--prepare-only"}
	listenPort := onceStringFlag{name: "--listen-port"}
	proofPath := onceStringFlag{name: "--proof"}
	restart := onceStringFlag{name: "--restart"}
	flags.Var(&yes, "yes", "skip interactive confirmation")
	flags.Var(&prepareOnly, "prepare-only", "stage local generation without activating production state")
	flags.Var(&listenPort, "listen-port", "loopback listen port (default 15432)")
	flags.Var(&proofPath, "proof", "path to server enrollment proof JSON")
	flags.Var(&restart, "restart", "durable restart policy: unless-stopped or manual")
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
	restartPolicy, err := routestate.ParseRestartPolicy(restart.value)
	if err != nil {
		return err
	}

	if !yes.value {
		fmt.Fprintf(stderr, "WarpTweet enrollment request\n")
		fmt.Fprintf(stderr, "  invite:     %s\n", view.InviteID)
		fmt.Fprintf(stderr, "  server:     %s:%d\n", view.ServerAddress, view.ServerPort)
		fmt.Fprintf(stderr, "  target:     %s:%d\n", view.TargetAddress, view.TargetPort)
		fmt.Fprintf(stderr, "  principal:  %s\n", view.Principal)
		fmt.Fprintf(stderr, "  profile:    %s\n", view.ProfileID)
		fmt.Fprintf(stderr, "  local bind: %s:%d\n", view.ListenAddress, view.ListenPort)
		fmt.Fprintf(stderr, "  access:     %ds\n", view.AuthorizationDurationSeconds)
		fmt.Fprintf(stderr, "  host key:   %s\n", truncateMiddle(view.HostPublicKey, 72))
		fmt.Fprintf(stderr, "Type ENROLL to continue: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) != "ENROLL" {
			return errors.New("enrollment aborted")
		}
	}
	var offlineProof json.RawMessage
	if proofPath.value != "" {
		proofRaw, err := os.ReadFile(proofPath.value)
		if err != nil {
			return err
		}
		offlineProof = proofRaw
	}
	if handled, err := callInstalledProvisioner(ctx, provisioner.Request{
		Version:       provisioner.ProtocolVersion,
		Action:        provisioner.ActionEnroll,
		Invite:        append(json.RawMessage(nil), raw...),
		Proof:         offlineProof,
		ListenPort:    view.ListenPort,
		RestartPolicy: restartPolicy,
		PrepareOnly:   prepareOnly.value,
	}, stdout); handled {
		return err
	}
	routeStore, err := productionRouteStore()
	if err != nil {
		return err
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	pending, stageRoot, identityPath, err := loadOrCreatePendingEnrollment(
		ctx,
		layout.ClientManifestPath,
		keygenPath(layout),
		invite,
		view.TunnelID,
	)
	if err != nil {
		return err
	}
	generationID := pending.Generation
	publicKey := pending.PublicKey
	managementToken := pending.ManagementToken

	if !prepareOnly.value {
		if err := persistReservedRoute(routeStore, view.TunnelID, view.ListenPort, invite.InviteID, generationID); err != nil {
			return err
		}
	}

	request := enrollment.EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           invite.Nonce,
		ClientName:      invite.ClientName,
		PublicKey:       publicKey,
		ProfileID:       invite.ProfileID,
		TunnelID:        view.TunnelID,
		ListenAddress:   view.ListenAddress,
		ListenPort:      view.ListenPort,
		ManagementToken: managementToken,
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
		if err := json.Unmarshal(offlineProof, &proof); err != nil {
			return fmt.Errorf("parse enrollment proof: %w", err)
		}
		if err := enrollment.ValidateEnrollmentProof(proof, invite, publicKey); err != nil {
			return err
		}
	} else if !prepareOnly.value {
		submitted, err := enrollment.SubmitEnrollment(ctx, invite, request)
		if err != nil {
			return fmt.Errorf("enrollment endpoint: %w (or pass --proof <server-proof.json>)", err)
		}
		proof = submitted
	}

	sshDigest, err := fileSHA256(layout.SSHPath)
	if err != nil {
		sshDigest, err = fileSHA256(installlayout.SSHPath)
		if err != nil {
			return fmt.Errorf("hash ssh engine: %w", err)
		}
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

	serviceEndpoint := fmt.Sprintf("%s:%d", view.TargetAddress, view.TargetPort)
	listenEndpoint := fmt.Sprintf("%s:%d", view.ListenAddress, view.ListenPort)

	if !prepareOnly.value {
		if proof.AuthorizationNotAfter == "" || proof.AuthorizationDurationSeconds <= 0 {
			return errors.New("enrollment proof missing host authorization expiry")
		}
		if _, err := grant.ParseUTC(proof.AuthorizationNotAfter); err != nil {
			return fmt.Errorf("enrollment proof authorization_not_after: %w", err)
		}
	}

	if prepareOnly.value {
		return writeJSON(stdout, map[string]any{
			"status":                  "prepared",
			"tunnel_id":               view.TunnelID,
			"listen_endpoint":         listenEndpoint,
			"service_endpoint":        serviceEndpoint,
			"enrollment_request_path": filepath.Join(stageRoot, "enrollment-request.json"),
			"stage_directory":         stageRoot,
			"identity_public_key":     publicKey,
			"profile_id":              profile.CurrentID,
			"target_health":           lifecycle.TargetHealthNotChecked,
		})
	}

	generationDir, err := routeStore.GenerationDir(view.TunnelID, generationID)
	if err != nil {
		return err
	}
	if err := ensureRouteGenerationDirectories(generationDir); err != nil {
		return err
	}
	if err := activateGeneration(
		filepath.Join(generationDir, "client.wt"),
		filepath.Join(generationDir, "identity"),
		filepath.Join(generationDir, "known_hosts"),
		filepath.Join(generationDir, "known_hosts.empty"),
		identityPath,
		manifestStage,
		knownHostsStage,
		emptyTrust,
	); err != nil {
		return err
	}
	if err := routeStore.Activate(view.TunnelID, generationID); err != nil {
		return err
	}

	enrollPort := proof.EnrollPort
	if enrollPort == 0 {
		enrollPort = invite.EnrollmentPort()
	}
	receipt := enrollmentReceipt{
		InviteID:                     invite.InviteID,
		ClientID:                     proof.ClientID,
		TunnelID:                     view.TunnelID,
		AcceptedAt:                   proof.AcceptedAt,
		AuthorizationNotAfter:        proof.AuthorizationNotAfter,
		AuthorizationDurationSeconds: proof.AuthorizationDurationSeconds,
		Generation:                   generationID,
		ManagementToken:              managementToken,
		ServerAddress:                firstNonEmptyString(proof.ServerAddress, invite.ServerAddress),
		EnrollPort:                   enrollPort,
		PublicKey:                    publicKey,
		HostPublicKey:                invite.HostPublicKey,
		EnrollmentTLSSPKISHA256:      invite.EnrollmentTLSSPKISHA256,
		Target:                       serviceEndpoint,
		Principal:                    invite.Principal,
		ProfileID:                    invite.ProfileID,
	}
	if err := writeEnrollmentReceipt(layout.ClientManifestPath, receipt); err != nil {
		return err
	}
	if err := persistRouteEnrollment(view.TunnelID, listenEndpoint, receipt, restartPolicy); err != nil {
		_ = routeStore.WriteTransaction(routestate.Transaction{
			RouteID:    view.TunnelID,
			Phase:      routestate.PhaseFailed,
			ListenPort: view.ListenPort,
			InviteID:   invite.InviteID,
			Generation: generationID,
			Error:      err.Error(),
		})
		return err
	}
	if err := persistEnrolledRoute(routeStore, view.TunnelID, view.ListenPort, invite.InviteID, generationID); err != nil {
		return err
	}
	if err := os.RemoveAll(stageRoot); err != nil {
		return fmt.Errorf("remove completed pending enrollment: %w", err)
	}

	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	_ = store.Write(lifecycle.State{
		TunnelID:       view.TunnelID,
		Phase:          lifecycle.PhaseStopped,
		ListenEndpoint: listenEndpoint,
		TargetHealth:   lifecycle.TargetHealthNotChecked,
		Generation:     generationID,
	})

	return writeJSON(stdout, map[string]any{
		"status":                         "enrolled",
		"tunnel_id":                      view.TunnelID,
		"route_id":                       view.TunnelID,
		"client_id":                      proof.ClientID,
		"listen_endpoint":                listenEndpoint,
		"service_endpoint":               serviceEndpoint,
		"generation":                     generationID,
		"authorization_not_after":        proof.AuthorizationNotAfter,
		"authorization_duration_seconds": proof.AuthorizationDurationSeconds,
		"desired_state":                  routestate.DesiredRunning,
		"restart_policy":                 restartPolicy,
		"target_health":                  lifecycle.TargetHealthNotChecked,
		"next":                           "warptweet up " + view.TunnelID,
	})
}

func runRepair(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	flags := newFlagSet("repair", stderr)
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("repair requires exactly one route id")
	}
	if handled, err := callInstalledProvisioner(ctx, provisioner.Request{
		Version:  provisioner.ProtocolVersion,
		Action:   provisioner.ActionRepair,
		TunnelID: positionals[0],
	}, stdout); handled {
		return err
	}
	return runUp(ctx, []string{positionals[0]}, stdout, stderr, dependencies)
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
	if handled, err := callInstalledProvisioner(ctx, provisioner.Request{
		Version: provisioner.ProtocolVersion, Action: provisioner.ActionUp,
		TunnelID: tunnelID, Once: once.value,
	}, stdout); handled {
		return err
	}
	if dependencies.loadProductionClientManifest == nil {
		return errors.New("production client manifest loader is required")
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	if err := writeRouteDesiredState(tunnelID, routestate.DesiredRunning, "", currentBootID()); err != nil {
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
	if current.Phase == lifecycle.PhaseReady && current.Generation != "" {
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
	if err := projectManagedTunnel(ctx, tunnelID, true); err != nil {
		_ = store.Write(lifecycle.State{TunnelID: tunnelID, Phase: lifecycle.PhaseFailed, Error: err.Error(), TargetHealth: lifecycle.TargetHealthNotChecked})
		return err
	}
	state, err := store.Read(tunnelID)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"status":          "started",
		"tunnel_id":       tunnelID,
		"phase":           state.Phase,
		"pid":             state.PID,
		"listen_endpoint": state.ListenEndpoint,
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

	if len(positionals) > 1 {
		return errors.New("status accepts at most one tunnel-id")
	}
	tunnelID := ""
	if len(positionals) == 1 {
		tunnelID = positionals[0]
	}
	if handled, err := callInstalledProvisioner(context.Background(), provisioner.Request{
		Version: provisioner.ProtocolVersion, Action: provisioner.ActionStatus, TunnelID: tunnelID,
	}, stdout); handled {
		return err
	}
	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	if len(positionals) == 1 {
		state, err := store.Read(positionals[0])
		if err != nil {
			return err
		}
		payload := routeStatusPayload(positionals[0], state)
		if useJSON {
			return writeJSON(stdout, payload)
		}
		fmt.Fprintf(stdout, "%s %s desired=%s listen=%s target_health=%s pid=%d\n",
			state.TunnelID, payload["actual_state"], payload["desired_state"], state.ListenEndpoint, state.TargetHealth, state.PID)
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
	if handled, err := callInstalledProvisioner(context.Background(), provisioner.Request{
		Version: provisioner.ProtocolVersion, Action: provisioner.ActionDown, TunnelID: tunnelID,
	}, stdout); handled {
		return err
	}
	if err := writeRouteDesiredState(tunnelID, routestate.DesiredStopped, "", ""); err != nil {
		return err
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
	if err := projectManagedTunnel(context.Background(), tunnelID, false); err != nil {
		_ = store.Write(lifecycle.State{
			TunnelID:       tunnelID,
			Phase:          lifecycle.PhaseFailed,
			ListenEndpoint: state.ListenEndpoint,
			TargetHealth:   lifecycle.TargetHealthNotChecked,
			Generation:     state.Generation,
			Error:          err.Error(),
		})
		return err
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

func runRotate(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("rotate", stderr)
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("rotate requires exactly one tunnel-id")
	}
	tunnelID := positionals[0]
	_ = stderr
	if handled, err := callInstalledProvisioner(ctx, provisioner.Request{
		Version: provisioner.ProtocolVersion, Action: provisioner.ActionRotate, TunnelID: tunnelID,
	}, stdout); handled {
		return err
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	lock, err := store.AdminLock(tunnelID)
	if err != nil {
		return err
	}
	defer lifecycle.Unlock(lock)

	receipt, err := loadEnrollmentReceipt(layout.ClientManifestPath, tunnelID)
	if err != nil {
		return err
	}
	if receipt.ManagementToken == "" || receipt.ClientID == "" {
		return errors.New("enrollment receipt missing management token; re-enroll before rotate")
	}

	pending, stageRoot, identityPath, err := loadOrCreatePendingRotation(ctx, layout.ClientManifestPath, keygenPath(layout), receipt, tunnelID)
	if err != nil {
		return err
	}
	generationID := pending.Generation
	publicKey := pending.PublicKey

	if receipt.EnrollmentTLSSPKISHA256 == "" {
		return errors.New("enrollment receipt missing TLS SPKI pin; re-enroll before rotate")
	}
	mgmtPort, err := managementLocalPort(store, tunnelID)
	if err != nil {
		return err
	}
	rotateReq := enrollment.ManagementRequest{
		ClientID:            receipt.ClientID,
		ManagementToken:     pending.CurrentManagementToken,
		TunnelID:            tunnelID,
		NewPublicKey:        publicKey,
		NextManagementToken: pending.NextManagementToken,
	}
	proof, err := enrollment.SubmitRotate(ctx, "127.0.0.1", mgmtPort, "", rotateReq)
	if err != nil && ctx.Err() == nil {
		first := err
		proof, err = enrollment.SubmitRotate(ctx, "127.0.0.1", mgmtPort, "", rotateReq)
		if err != nil {
			return fmt.Errorf("host rotate: %w (first attempt: %v)", err, first)
		}
	} else if err != nil {
		return fmt.Errorf("host rotate: %w", err)
	}
	failCleanup := func(err error) error {
		return persistCleanupRequired(store, tunnelID, generationID, "rotate", err)
	}

	receipt.ManagementToken = pending.NextManagementToken
	receipt.PublicKey = publicKey
	receipt.AcceptedAt = proof.AcceptedAt
	if proof.EnrollPort != 0 {
		receipt.EnrollPort = proof.EnrollPort
	}
	if err := writeEnrollmentReceipt(layout.ClientManifestPath, receipt); err != nil {
		return failCleanup(err)
	}
	if err := syncRouteReceipt(tunnelID, receipt); err != nil {
		slog.Error("route receipt sync failed after rotate", "route_id", tunnelID, "err", err)
	}

	emptyTrust := filepath.Join(stageRoot, "known_hosts.empty")
	if err := os.WriteFile(emptyTrust, nil, 0o600); err != nil {
		return failCleanup(err)
	}
	if err := copyFile(layout.ClientManifestPath, filepath.Join(stageRoot, "client.wt"), 0o600); err != nil {
		return failCleanup(err)
	}
	if err := copyFile(layout.ClientKnownHostsPath, filepath.Join(stageRoot, "known_hosts"), 0o600); err != nil {
		return failCleanup(err)
	}
	if err := activateGeneration(
		layout.ClientManifestPath,
		layout.ClientIdentityPath,
		layout.ClientKnownHostsPath,
		layout.ClientGlobalKnownHostsPath,
		identityPath,
		filepath.Join(stageRoot, "client.wt"),
		filepath.Join(stageRoot, "known_hosts"),
		emptyTrust,
	); err != nil {
		return failCleanup(err)
	}

	receipt.Generation = generationID
	if err := writeEnrollmentReceipt(layout.ClientManifestPath, receipt); err != nil {
		return failCleanup(err)
	}
	if err := syncRouteReceipt(tunnelID, receipt); err != nil {
		slog.Error("route receipt sync failed after rotate", "route_id", tunnelID, "err", err)
	}
	if err := os.RemoveAll(stageRoot); err != nil {
		return failCleanup(fmt.Errorf("remove completed pending rotation: %w", err))
	}
	state, _ := store.Read(tunnelID)
	result := map[string]any{
		"status":        "rotated",
		"tunnel_id":     tunnelID,
		"client_id":     receipt.ClientID,
		"generation":    generationID,
		"target_health": lifecycle.TargetHealthNotChecked,
	}
	if managedTunnelRunning(state) {
		state.Generation = generationID
		if err := store.Write(state); err != nil {
			return failCleanup(err)
		}
		if err := projectManagedTunnel(ctx, tunnelID, false); err == nil {
			if err := projectManagedTunnel(ctx, tunnelID, true); err == nil {
				result["running"] = true
				return writeJSON(stdout, result)
			}
		}
	}
	if err := stopTunnelProcess(ctx, store, tunnelID); err != nil {
		return failCleanup(err)
	}
	_ = store.Write(lifecycle.State{
		TunnelID:     tunnelID,
		Phase:        lifecycle.PhaseStopped,
		TargetHealth: lifecycle.TargetHealthNotChecked,
		Generation:   generationID,
	})
	result["next"] = "warptweet up " + tunnelID
	return writeJSON(stdout, result)
}

func runRevokeTunnel(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("revoke", stderr)
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("revoke requires exactly one tunnel-id")
	}
	tunnelID := positionals[0]
	_ = stderr
	if handled, err := callInstalledProvisioner(ctx, provisioner.Request{
		Version: provisioner.ProtocolVersion, Action: provisioner.ActionRevoke, TunnelID: tunnelID,
	}, stdout); handled {
		return err
	}

	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	store := lifecycle.Store{Root: layout.ClientRuntimeRoot}
	lock, err := store.AdminLock(tunnelID)
	if err != nil {
		return err
	}
	defer lifecycle.Unlock(lock)

	receipt, err := loadEnrollmentReceipt(layout.ClientManifestPath, tunnelID)
	if err != nil {
		return err
	}
	if receipt.ManagementToken == "" || receipt.ClientID == "" {
		return errors.New("enrollment receipt missing management token; use server revoke on the host")
	}
	if receipt.EnrollmentTLSSPKISHA256 == "" {
		return errors.New("enrollment receipt missing TLS SPKI pin; use server revoke on the host")
	}
	mgmtPort, err := managementLocalPort(store, tunnelID)
	if err != nil {
		return err
	}
	if err := enrollment.SubmitRevoke(ctx, "127.0.0.1", mgmtPort, "", enrollment.ManagementRequest{
		ClientID:        receipt.ClientID,
		ManagementToken: receipt.ManagementToken,
		TunnelID:        tunnelID,
	}); err != nil {
		return fmt.Errorf("host revoke: %w", err)
	}
	failCleanup := func(err error) error {
		return persistCleanupRequired(store, tunnelID, receipt.Generation, "revoke", err)
	}

	receipt.ManagementToken = ""
	receipt.RevokedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeEnrollmentReceipt(layout.ClientManifestPath, receipt); err != nil {
		return failCleanup(err)
	}
	if err := syncRouteReceipt(tunnelID, receipt); err != nil {
		slog.Error("route receipt sync failed after revoke", "route_id", tunnelID, "err", err)
	}
	if err := stopTunnelProcess(ctx, store, tunnelID); err != nil {
		return failCleanup(err)
	}
	_ = store.Write(lifecycle.State{
		TunnelID:     tunnelID,
		Phase:        lifecycle.PhaseStopped,
		TargetHealth: lifecycle.TargetHealthNotChecked,
		Generation:   receipt.Generation,
	})
	return writeJSON(stdout, map[string]any{
		"status":        "revoked",
		"tunnel_id":     tunnelID,
		"client_id":     receipt.ClientID,
		"host":          "acknowledged",
		"identity":      "preserved_local",
		"target_health": lifecycle.TargetHealthNotChecked,
	})
}

type enrollmentReceipt struct {
	InviteID                     string `json:"invite_id"`
	ClientID                     string `json:"client_id"`
	TunnelID                     string `json:"tunnel_id"`
	AcceptedAt                   string `json:"accepted_at"`
	AuthorizationNotAfter        string `json:"authorization_not_after,omitempty"`
	AuthorizationDurationSeconds int64  `json:"authorization_duration_seconds,omitempty"`
	Generation                   string `json:"generation"`
	ManagementToken              string `json:"management_token,omitempty"`
	ServerAddress                string `json:"server_address"`
	EnrollPort                   uint16 `json:"enroll_port,omitempty"`
	PublicKey                    string `json:"public_key,omitempty"`
	HostPublicKey                string `json:"host_public_key,omitempty"`
	EnrollmentTLSSPKISHA256      string `json:"enrollment_tls_spki_sha256"`
	Target                       string `json:"target,omitempty"`
	Principal                    string `json:"principal,omitempty"`
	ProfileID                    string `json:"profile_id,omitempty"`
	RevokedAt                    string `json:"revoked_at,omitempty"`
}

type pendingRotation struct {
	ClientID               string `json:"client_id"`
	TunnelID               string `json:"tunnel_id"`
	Generation             string `json:"generation"`
	PublicKey              string `json:"public_key"`
	CurrentManagementToken string `json:"current_management_token"`
	NextManagementToken    string `json:"next_management_token"`
}

type pendingEnrollment struct {
	InviteID        string `json:"invite_id"`
	TunnelID        string `json:"tunnel_id"`
	Generation      string `json:"generation"`
	PublicKey       string `json:"public_key"`
	ManagementToken string `json:"management_token"`
}

func loadOrCreatePendingEnrollment(
	ctx context.Context,
	clientManifestPath string,
	keygen string,
	invite enrollment.Invite,
	tunnelID string,
) (pendingEnrollment, string, string, error) {
	root := filepath.Join(enrollmentReceiptDir(clientManifestPath), "pending-enrollment")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return pendingEnrollment{}, "", "", err
	}
	if !enrollment.IsHexID(invite.InviteID) {
		return pendingEnrollment{}, "", "", fmt.Errorf("invite_id is invalid")
	}
	directory := filepath.Join(root, invite.InviteID)
	statePath := filepath.Join(directory, "enrollment.json")
	identityPath := filepath.Join(directory, "client")
	var pending pendingEnrollment
	found, err := loadPendingJSONState(statePath, &pending)
	if err != nil {
		return pendingEnrollment{}, "", "", fmt.Errorf("parse pending enrollment: %w", err)
	}
	if found {
		if pending.InviteID != invite.InviteID || pending.TunnelID != tunnelID ||
			enrollment.ValidateManagementToken(pending.ManagementToken) != nil {
			return pendingEnrollment{}, "", "", errors.New("pending enrollment does not match the invite")
		}
		if err := verifyPendingIdentityPublicKey(identityPath, pending.PublicKey, "pending enrollment public key changed"); err != nil {
			return pendingEnrollment{}, "", "", err
		}
		return pending, directory, identityPath, nil
	}
	publicKey, err := createPendingClientIdentity(ctx, keygen, directory, identityPath, "warptweet-client-"+tunnelID, "generate client key")
	if err != nil {
		return pendingEnrollment{}, "", "", err
	}
	token, err := enrollment.GenerateManagementToken()
	if err != nil {
		return pendingEnrollment{}, "", "", err
	}
	pending = pendingEnrollment{
		InviteID:        invite.InviteID,
		TunnelID:        tunnelID,
		Generation:      time.Now().UTC().Format("20060102T150405.000000000Z"),
		PublicKey:       publicKey,
		ManagementToken: token,
	}
	if err := writePendingJSONState(statePath, pending); err != nil {
		return pendingEnrollment{}, "", "", err
	}
	return pending, directory, identityPath, nil
}

func loadOrCreatePendingRotation(
	ctx context.Context,
	clientManifestPath string,
	keygen string,
	receipt enrollmentReceipt,
	tunnelID string,
) (pendingRotation, string, string, error) {
	root := filepath.Join(enrollmentReceiptDir(clientManifestPath), "pending-rotation")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return pendingRotation{}, "", "", err
	}
	directory := filepath.Join(root, tunnelID)
	statePath := filepath.Join(directory, "rotation.json")
	identityPath := filepath.Join(directory, "client")
	var pending pendingRotation
	found, err := loadPendingJSONState(statePath, &pending)
	if err != nil {
		return pendingRotation{}, "", "", fmt.Errorf("parse pending rotation: %w", err)
	}
	if found {
		if pending.ClientID != receipt.ClientID || pending.TunnelID != tunnelID ||
			(pending.CurrentManagementToken != receipt.ManagementToken && pending.NextManagementToken != receipt.ManagementToken) ||
			enrollment.ValidateManagementToken(pending.CurrentManagementToken) != nil ||
			enrollment.ValidateManagementToken(pending.NextManagementToken) != nil {
			return pendingRotation{}, "", "", errors.New("pending rotation does not match the enrollment receipt")
		}
		if err := verifyPendingIdentityPublicKey(identityPath, pending.PublicKey, "pending rotation public key changed"); err != nil {
			return pendingRotation{}, "", "", err
		}
		return pending, directory, identityPath, nil
	}
	publicKey, err := createPendingClientIdentity(ctx, keygen, directory, identityPath, "warptweet-client-"+tunnelID, "generate rotated client key")
	if err != nil {
		return pendingRotation{}, "", "", err
	}
	nextToken, err := enrollment.GenerateManagementToken()
	if err != nil {
		return pendingRotation{}, "", "", err
	}
	pending = pendingRotation{
		ClientID:               receipt.ClientID,
		TunnelID:               tunnelID,
		Generation:             time.Now().UTC().Format("20060102T150405.000000000Z"),
		PublicKey:              publicKey,
		CurrentManagementToken: receipt.ManagementToken,
		NextManagementToken:    nextToken,
	}
	if err := writePendingJSONState(statePath, pending); err != nil {
		return pendingRotation{}, "", "", err
	}
	return pending, directory, identityPath, nil
}

func loadPendingJSONState(statePath string, destination any) (bool, error) {
	raw, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, err
	}
	return true, nil
}

func verifyPendingIdentityPublicKey(identityPath, wantPublicKey, mismatchMessage string) error {
	publicKeyBytes, err := os.ReadFile(identityPath + ".pub")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(publicKeyBytes)) != wantPublicKey {
		return errors.New(mismatchMessage)
	}
	return nil
}

func createPendingClientIdentity(ctx context.Context, keygen, directory, identityPath, comment, failurePrefix string) (string, error) {
	if err := os.RemoveAll(directory); err != nil {
		return "", err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, keygen,
		"-t", "mldsa44-ed25519",
		"-f", identityPath,
		"-N", "",
		"-C", comment,
	)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s: %w (%s)", failurePrefix, err, strings.TrimSpace(string(output)))
	}
	publicKeyBytes, err := os.ReadFile(identityPath + ".pub")
	if err != nil {
		return "", err
	}
	publicKey := strings.TrimSpace(string(publicKeyBytes))
	if publicKey == "" || strings.ContainsAny(publicKey, "\r\n") {
		return "", errors.New("client public key must be one line")
	}
	return publicKey, nil
}

func writePendingJSONState(statePath string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath, append(raw, '\n'), 0o600)
}

func persistCleanupRequired(store lifecycle.Store, tunnelID, generation, operation string, cleanupErr error) error {
	message := fmt.Sprintf("host %s completed; tunnel cleanup still required: %v", operation, cleanupErr)
	_ = store.Write(lifecycle.State{
		TunnelID:     tunnelID,
		Phase:        lifecycle.PhaseCleanupRequired,
		TargetHealth: lifecycle.TargetHealthNotChecked,
		Generation:   generation,
		Error:        message,
	})
	return errors.New(message)
}

func managementLocalPort(store lifecycle.Store, tunnelID string) (uint16, error) {
	state, err := store.Read(tunnelID)
	if err != nil {
		return 0, err
	}
	if state.ListenEndpoint == "" {
		return 0, fmt.Errorf("route %s has no listen endpoint; start the tunnel before rotate or revoke", tunnelID)
	}
	_, portText, err := net.SplitHostPort(state.ListenEndpoint)
	if err != nil {
		return 0, fmt.Errorf("route %s listen endpoint %q is invalid: %w", tunnelID, state.ListenEndpoint, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || port == 65535 {
		return 0, fmt.Errorf("route %s listen port %q cannot host a management forward", tunnelID, portText)
	}
	return uint16(port) + 1, nil
}

func managedTunnelRunning(state lifecycle.State) bool {
	if state.PID <= 0 || !processAlivePID(state.PID) {
		return false
	}
	switch state.Phase {
	case lifecycle.PhaseStarting, lifecycle.PhaseAwaitingReadiness, lifecycle.PhaseReady, lifecycle.PhaseBackoff:
		return true
	default:
		return false
	}
}

func (receipt enrollmentReceipt) enrollPortOrDefault() uint16 {
	if receipt.EnrollPort == 0 {
		return enrollment.DefaultEnrollmentPort
	}
	return receipt.EnrollPort
}

func enrollmentReceiptDir(clientManifestPath string) string {
	return filepath.Join(filepath.Dir(clientManifestPath), "enrollment")
}

func writeEnrollmentReceipt(clientManifestPath string, receipt enrollmentReceipt) error {
	dir := enrollmentReceiptDir(clientManifestPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomic(filepath.Join(dir, receipt.TunnelID+".json"), raw, 0o600)
}

func stopTunnelProcess(ctx context.Context, store lifecycle.Store, tunnelID string) error {
	if _, err := store.Read(tunnelID); err != nil {
		return err
	}
	return projectManagedTunnel(ctx, tunnelID, false)
}

func loadEnrollmentReceipt(clientManifestPath, tunnelID string) (enrollmentReceipt, error) {
	path := filepath.Join(enrollmentReceiptDir(clientManifestPath), tunnelID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return enrollmentReceipt{}, fmt.Errorf("load enrollment receipt for %s: %w", tunnelID, err)
	}
	var receipt enrollmentReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return enrollmentReceipt{}, fmt.Errorf("parse enrollment receipt: %w", err)
	}
	if receipt.TunnelID == "" {
		receipt.TunnelID = tunnelID
	}
	return receipt, nil
}

func productionRouteStore() (routestate.Store, error) {
	layout, err := productionClientLayout()
	if err != nil {
		return routestate.Store{}, err
	}
	root := installlayout.ClientRoutesDirectory
	if runtime.GOOS == "darwin" {
		root = installlayout.DarwinClientRoutesDirectory
	}
	if dir := filepath.Dir(layout.ClientManifestPath); dir != installlayout.ClientStateRoot && dir != installlayout.DarwinClientStateRoot {
		root = filepath.Join(dir, "routes")
	}
	return routestate.Store{Root: root}, nil
}

func openRouteStore(dependencies commandDependencies) (routeStore, error) {
	if dependencies.openRouteStore != nil {
		return dependencies.openRouteStore()
	}
	return productionRouteStore()
}

func invokeEnroll(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	if dependencies.enroll != nil {
		return dependencies.enroll(ctx, arguments, stdout, stderr)
	}
	return runEnroll(ctx, arguments, stdout, stderr)
}

func invokeUp(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	if dependencies.up != nil {
		return dependencies.up(ctx, arguments, stdout, stderr, dependencies)
	}
	return runUp(ctx, arguments, stdout, stderr, dependencies)
}

func invokeRepair(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	if dependencies.repair != nil {
		return dependencies.repair(ctx, arguments, stdout, stderr, dependencies)
	}
	return runRepair(ctx, arguments, stdout, stderr, dependencies)
}

type reservedRouteStore interface {
	ReserveAndWriteTransaction(routestate.Transaction) error
}

func persistReservedRoute(store reservedRouteStore, routeID string, listenPort uint16, inviteID, generation string) error {
	return store.ReserveAndWriteTransaction(routestate.Transaction{
		RouteID:    routeID,
		Phase:      routestate.PhaseReserved,
		ListenPort: listenPort,
		InviteID:   inviteID,
		Generation: generation,
	})
}

func persistEnrolledRoute(store routeStore, routeID string, listenPort uint16, inviteID, generation string) error {
	return store.WriteTransaction(routestate.Transaction{
		RouteID:    routeID,
		Phase:      routestate.PhaseEnrolled,
		ListenPort: listenPort,
		InviteID:   inviteID,
		Generation: generation,
	})
}

func persistRouteEnrollment(routeID, listenEndpoint string, receipt enrollmentReceipt, restartPolicy string) error {
	store, err := productionRouteStore()
	if err != nil {
		return err
	}
	exists, err := store.Exists(routeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: route %q was not reserved before enrollment", routestate.ErrInvalidRoute, routeID)
	}
	if err := store.WriteReceipt(routestate.Receipt{
		InviteID:                     receipt.InviteID,
		ClientID:                     receipt.ClientID,
		RouteID:                      routeID,
		AcceptedAt:                   receipt.AcceptedAt,
		AuthorizationNotAfter:        receipt.AuthorizationNotAfter,
		AuthorizationDurationSeconds: receipt.AuthorizationDurationSeconds,
		Generation:                   receipt.Generation,
		ManagementToken:              receipt.ManagementToken,
		ServerAddress:                receipt.ServerAddress,
		EnrollPort:                   receipt.EnrollPort,
		PublicKey:                    receipt.PublicKey,
		HostPublicKey:                receipt.HostPublicKey,
		EnrollmentTLSSPKISHA256:      receipt.EnrollmentTLSSPKISHA256,
		Target:                       receipt.Target,
		ListenEndpoint:               listenEndpoint,
		Principal:                    receipt.Principal,
		ProfileID:                    receipt.ProfileID,
		RevokedAt:                    receipt.RevokedAt,
	}); err != nil {
		return err
	}
	return store.WriteIntent(routestate.Intent{
		Kind:          routestate.KindDesiredState,
		SchemaVersion: routestate.CurrentSchemaVersion,
		RouteID:       routeID,
		DesiredState:  routestate.DesiredRunning,
		RestartPolicy: restartPolicy,
		BootID:        currentBootID(),
	})
}

func persistConnectDesiredState(routeID, restartPolicy string) error {
	store, err := productionRouteStore()
	if err != nil {
		return err
	}
	exists, err := store.Exists(routeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: route %q is not reserved; enroll before setting --restart", routestate.ErrInvalidRoute, routeID)
	}
	intent, err := store.LoadIntent(routeID)
	if err != nil {
		intent = routestate.Intent{
			Kind:          routestate.KindDesiredState,
			SchemaVersion: routestate.CurrentSchemaVersion,
			RouteID:       routeID,
		}
	}
	intent.RestartPolicy = restartPolicy
	intent.DesiredState = routestate.DesiredRunning
	if restartPolicy == routestate.RestartManual {
		intent.BootID = currentBootID()
	}
	return store.WriteIntent(intent)
}

func syncRouteReceipt(routeID string, receipt enrollmentReceipt) error {
	store, err := productionRouteStore()
	if err != nil {
		return err
	}
	exists, err := store.Exists(routeID)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	current, err := store.LoadReceipt(routeID)
	if err != nil {
		current = routestate.Receipt{RouteID: routeID}
	}
	current.InviteID = firstNonEmptyString(receipt.InviteID, current.InviteID)
	current.ClientID = firstNonEmptyString(receipt.ClientID, current.ClientID)
	current.RouteID = routeID
	current.AcceptedAt = firstNonEmptyString(receipt.AcceptedAt, current.AcceptedAt)
	if receipt.AuthorizationNotAfter != "" {
		current.AuthorizationNotAfter = receipt.AuthorizationNotAfter
	}
	if receipt.AuthorizationDurationSeconds > 0 {
		current.AuthorizationDurationSeconds = receipt.AuthorizationDurationSeconds
	}
	current.Generation = firstNonEmptyString(receipt.Generation, current.Generation)
	current.ManagementToken = receipt.ManagementToken
	current.ServerAddress = firstNonEmptyString(receipt.ServerAddress, current.ServerAddress)
	if receipt.EnrollPort != 0 {
		current.EnrollPort = receipt.EnrollPort
	}
	current.PublicKey = firstNonEmptyString(receipt.PublicKey, current.PublicKey)
	current.HostPublicKey = firstNonEmptyString(receipt.HostPublicKey, current.HostPublicKey)
	current.EnrollmentTLSSPKISHA256 = firstNonEmptyString(receipt.EnrollmentTLSSPKISHA256, current.EnrollmentTLSSPKISHA256)
	current.Target = firstNonEmptyString(receipt.Target, current.Target)
	current.Principal = firstNonEmptyString(receipt.Principal, current.Principal)
	current.ProfileID = firstNonEmptyString(receipt.ProfileID, current.ProfileID)
	current.RevokedAt = receipt.RevokedAt
	return store.WriteReceipt(current)
}

func writeRouteDesiredState(routeID, desired, restartPolicy, bootID string) error {
	store, err := productionRouteStore()
	if err != nil {
		return err
	}
	exists, err := store.Exists(routeID)
	if err != nil {
		return err
	}
	if !exists {
		if err := store.Reserve(routeID); err != nil {
			return err
		}
	}
	intent, err := store.LoadIntent(routeID)
	if err != nil {
		intent = routestate.Intent{
			Kind:          routestate.KindDesiredState,
			SchemaVersion: routestate.CurrentSchemaVersion,
			RouteID:       routeID,
			RestartPolicy: routestate.RestartUnlessStopped,
		}
	}
	intent.DesiredState = desired
	if restartPolicy != "" {
		intent.RestartPolicy = restartPolicy
	}
	if desired == routestate.DesiredRunning && intent.RestartPolicy == routestate.RestartManual {
		if bootID == "" {
			bootID = currentBootID()
		}
		intent.BootID = bootID
	}
	if desired == routestate.DesiredStopped {
		intent.BootID = ""
	}
	return store.WriteIntent(intent)
}

func currentBootID() string {
	if runtime.GOOS == "linux" {
		contents, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err == nil {
			return strings.TrimSpace(string(contents))
		}
	}
	if runtime.GOOS == "darwin" {
		output, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.boottime").Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return ""
}

func routeStatusPayload(routeID string, state lifecycle.State) map[string]any {
	payload := map[string]any{
		"version":         1,
		"route_id":        routeID,
		"tunnel_id":       routeID,
		"actual_state":    state.Phase,
		"phase":           state.Phase,
		"listen_endpoint": state.ListenEndpoint,
		"target_health":   state.TargetHealth,
		"pid":             state.PID,
		"generation":      state.Generation,
		"last_error":      state.Error,
	}
	store, err := productionRouteStore()
	if err != nil {
		return payload
	}
	if intent, err := store.LoadIntent(routeID); err == nil {
		payload["desired_state"] = intent.DesiredState
		payload["restart_policy"] = intent.RestartPolicy
	}
	if receipt, err := store.LoadReceipt(routeID); err == nil {
		payload["client_id"] = receipt.ClientID
		payload["authorization_not_after"] = receipt.AuthorizationNotAfter
		payload["authorization_duration_seconds"] = receipt.AuthorizationDurationSeconds
		payload["server_endpoint"] = receipt.ServerAddress
		payload["target_endpoint"] = receipt.Target
		payload["authorization_state"] = authorizationState(receipt, state)
	}
	if payload["desired_state"] == nil {
		payload["desired_state"] = ""
	}
	return payload
}

func authorizationState(receipt routestate.Receipt, state lifecycle.State) string {
	if receipt.RevokedAt != "" {
		return "revoked"
	}
	if receipt.AuthorizationNotAfter == "" {
		return "invalid"
	}
	notAfter, err := grant.ParseUTC(receipt.AuthorizationNotAfter)
	if err != nil {
		return "invalid"
	}
	if grant.ReadyToExpire(notAfter, time.Now().UTC()) {
		if state.Phase == lifecycle.PhaseFailed || state.Error == "blocked-expired" {
			return "expired"
		}
		return "expiry_expected"
	}
	if state.Phase == lifecycle.PhaseReady {
		return "active"
	}
	return "valid"
}

func runRoutes(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("routes", stderr)
	asJSON := onceBoolFlag{name: "--json"}
	flags.Var(&asJSON, "json", "emit JSON")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	store, err := productionRouteStore()
	if err != nil {
		return err
	}
	listed, err := store.List()
	if err != nil {
		return err
	}
	type routeJSON struct {
		RouteID       string `json:"route_id"`
		DesiredState  string `json:"desired_state,omitempty"`
		RestartPolicy string `json:"restart_policy,omitempty"`
		Listen        string `json:"listen_endpoint,omitempty"`
		Target        string `json:"target_endpoint,omitempty"`
		Authorization string `json:"authorization_not_after,omitempty"`
		Invalid       bool   `json:"invalid"`
		Error         string `json:"error,omitempty"`
	}
	payload := make([]routeJSON, 0, len(listed))
	for _, route := range listed {
		payload = append(payload, routeJSON{
			RouteID:       route.RouteID,
			DesiredState:  route.Intent.DesiredState,
			RestartPolicy: route.Intent.RestartPolicy,
			Listen:        route.Listen,
			Target:        route.Receipt.Target,
			Authorization: route.Receipt.AuthorizationNotAfter,
			Invalid:       route.Invalid,
			Error:         route.Error,
		})
	}
	if asJSON.value || !asJSON.set {
		return writeJSON(stdout, map[string]any{"version": 1, "routes": payload})
	}
	for _, route := range payload {
		if route.Invalid {
			fmt.Fprintf(stdout, "%s invalid %s\n", route.RouteID, route.Error)
			continue
		}
		fmt.Fprintf(stdout, "%s %s restart=%s listen=%s\n", route.RouteID, route.DesiredState, route.RestartPolicy, route.Listen)
	}
	return nil
}

func runReconcile(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	flags := newFlagSet("reconcile", stderr)
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	store, err := productionRouteStore()
	if err != nil {
		return err
	}
	listed, err := store.List()
	if err != nil {
		return err
	}
	bootID := currentBootID()
	var started, skipped []string
	failed := map[string]string{}
	projectionErrors := map[string]string{}
	for _, route := range listed {
		if route.Invalid {
			skipped = append(skipped, route.RouteID)
			continue
		}
		if route.Receipt.ClientID == "" || route.Receipt.AuthorizationNotAfter == "" {
			skipped = append(skipped, route.RouteID)
			continue
		}
		notAfter, parseErr := grant.ParseUTC(route.Receipt.AuthorizationNotAfter)
		if parseErr != nil || grant.ReadyToExpire(notAfter, time.Now().UTC()) {
			skipped = append(skipped, route.RouteID)
			continue
		}
		if route.Receipt.RevokedAt != "" {
			skipped = append(skipped, route.RouteID)
			continue
		}
		if !routestate.ShouldStartAtBoot(route.Intent, bootID) {
			if route.Intent.DesiredState == routestate.DesiredStopped {
				if err := projectManagedTunnel(ctx, route.RouteID, false); err != nil {
					projectionErrors[route.RouteID] = err.Error()
				}
			}
			skipped = append(skipped, route.RouteID)
			continue
		}
		if err := projectManagedTunnel(ctx, route.RouteID, true); err != nil {
			failed[route.RouteID] = err.Error()
			continue
		}
		started = append(started, route.RouteID)
	}
	return writeJSON(stdout, map[string]any{
		"version":           1,
		"status":            "reconciled",
		"started":           started,
		"skipped":           skipped,
		"failed":            failed,
		"projection_errors": projectionErrors,
	})
}

func projectManagedTunnel(ctx context.Context, routeID string, start bool) error {
	if err := routestate.ValidateRouteID(routeID); err != nil {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		return projectLinuxTunnel(ctx, routeID, start)
	case "darwin":
		return fmt.Errorf("%w: start or reinstall the WarpTweet client package so the provisioner socket exists", outcome.ErrProvisionerUnavailable)
	default:
		return fmt.Errorf("%w: no service-manager projector for %s", outcome.ErrPackageBoundary, runtime.GOOS)
	}
}

func projectLinuxTunnel(ctx context.Context, routeID string, start bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("%w: systemctl is required to project warptweet-tunnel@%s", outcome.ErrPackageBoundary, routeID)
	}
	unit := "warptweet-tunnel@" + routeID + ".service"
	action := "stop"
	if start {
		action = "start"
	}
	cmd := exec.CommandContext(ctx, "systemctl", action, unit)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", action, unit, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
	stopErrors := map[string]string{}
	for _, state := range states {
		if err := projectManagedTunnel(context.Background(), state.TunnelID, false); err != nil {
			stopErrors[state.TunnelID] = err.Error()
			continue
		}
		_ = store.Write(lifecycle.State{
			TunnelID:       state.TunnelID,
			Phase:          lifecycle.PhaseStopped,
			ListenEndpoint: state.ListenEndpoint,
			TargetHealth:   lifecycle.TargetHealthNotChecked,
			Generation:     state.Generation,
		})
	}
	if err := writeJSON(stdout, map[string]any{
		"status":      "stopped_local_tunnels",
		"identity":    "preserved",
		"stop_errors": stopErrors,
		"note":        "package removal remains a platform package manager concern",
	}); err != nil {
		return err
	}
	if len(stopErrors) > 0 {
		return fmt.Errorf("uninstall: %d tunnels failed to stop", len(stopErrors))
	}
	return nil
}

func ensureRouteGenerationDirectories(generationDir string) error {
	generationsDir := filepath.Dir(generationDir)
	routeDir := filepath.Dir(generationsDir)
	for _, dir := range []string{routeDir, generationsDir, generationDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return err
		}
	}
	return ownClientStateFiles("", routeDir, generationsDir, generationDir)
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
	// OpenSSH refuses private keys with group/other bits (authfile "too open").
	if err := copyFile(stageIdentity, identityPath, 0o600); err != nil {
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
	if err := copyFile(stageEmpty, emptyTrustPath, 0o440); err != nil {
		return err
	}
	return ownClientStateFiles(
		identityPath,
		filepath.Dir(identityPath),
		filepath.Dir(knownHostsPath),
		identityPath,
		identityPath+".pub",
		manifestPath,
		knownHostsPath,
		emptyTrustPath,
	)
}

func copyFile(source, destination string, mode os.FileMode) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeFileAtomic(destination, contents, mode)
}

// ownClientStateFiles makes the private key service-owned at 0600 and keeps
// policy/trust root-owned with the service group able to read them.
func ownClientStateFiles(privateIdentityPath string, paths ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	groupName := installlayout.ClientServiceGroup
	if runtime.GOOS == "darwin" {
		groupName = installlayout.DarwinClientServiceGroup
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("lookup service group %q: %w", groupName, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("parse service group id %q: %w", group.Gid, err)
	}
	userName := installlayout.ClientServiceUser
	if runtime.GOOS == "darwin" {
		userName = installlayout.DarwinClientServiceUser
	}
	serviceUser, err := user.Lookup(userName)
	if err != nil {
		return fmt.Errorf("lookup service user %q: %w", userName, err)
	}
	uid, err := strconv.Atoi(serviceUser.Uid)
	if err != nil {
		return fmt.Errorf("parse service user id %q: %w", serviceUser.Uid, err)
	}
	cleanedIdentity := filepath.Clean(privateIdentityPath)
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		ownerUID := 0
		if filepath.Clean(path) == cleanedIdentity {
			ownerUID = uid
		}
		if err := os.Chown(path, ownerUID, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
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
