package provisioner

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/lifecycle"
	"warptweet.com/warptweet/internal/routestate"
)

type Server struct {
	mu sync.Mutex
}

type tunnelJob struct {
	loaded bool
	pid    int
}

func (server *Server) Serve(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("provisioner serve requires root")
	}
	serviceUID, serviceGID, err := lookupIdentity(
		installlayout.DarwinClientServiceUser,
		installlayout.DarwinClientServiceGroup,
	)
	if err != nil {
		return err
	}
	adminGroup, err := user.LookupGroup("admin")
	if err != nil {
		return fmt.Errorf("resolve macOS admin group: %w", err)
	}
	adminGID, err := parseID(adminGroup.Gid)
	if err != nil {
		return fmt.Errorf("parse macOS admin gid: %w", err)
	}
	if err := ensureSocketDirectory(); err != nil {
		return err
	}
	if err := removeStaleSocket(); err != nil {
		return err
	}
	address := &net.UnixAddr{Name: installlayout.DarwinProvisionerSocket, Net: "unix"}
	oldMask := syscall.Umask(0o077)
	listener, err := net.ListenUnix("unix", address)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listen on provisioner socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(installlayout.DarwinProvisionerSocket)
	if err := os.Chown(installlayout.DarwinProvisionerSocket, 0, int(adminGID)); err != nil {
		return fmt.Errorf("set provisioner socket ownership: %w", err)
	}
	if err := os.Chmod(installlayout.DarwinProvisionerSocket, 0o660); err != nil {
		return fmt.Errorf("set provisioner socket mode: %w", err)
	}

	go func() {
		if err := reconcileDarwinBoot(ctx, serviceUID, serviceGID); err != nil {
			slog.Error("darwin boot reconcile failed", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept provisioner request: %w", acceptErr)
		}
		go server.handleConnection(ctx, connection, serviceUID, serviceGID)
	}
}

func (server *Server) handleConnection(ctx context.Context, connection *net.UnixConn, serviceUID, serviceGID uint32) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(60 * time.Second))
	var request Request
	if err := decodeSingleJSON(connection, MaxRequestBytes, &request); err != nil {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		writeResponse(connection, Response{Error: "invalid provisioner request"})
		return
	}
	if err := ValidateRequest(request); err != nil {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		writeResponse(connection, Response{Error: err.Error()})
		return
	}
	if request.Action != ActionStatus {
		server.mu.Lock()
		defer server.mu.Unlock()
	}
	output, err := executeRequest(ctx, request, serviceUID, serviceGID)
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		writeResponse(connection, Response{Error: err.Error()})
		return
	}
	writeResponse(connection, Response{OK: true, Output: output})
}

func executeRequest(ctx context.Context, request Request, serviceUID, serviceGID uint32) (string, error) {
	switch request.Action {
	case ActionEnroll:
		return executeEnroll(ctx, request)
	case ActionConnect:
		output, err := executeEnroll(ctx, request)
		if err != nil || request.PrepareOnly {
			return output, err
		}
		tunnelID := enrollOutputTunnelID(output)
		if tunnelID == "" {
			return output, errors.New("connect enroll output missing tunnel_id")
		}
		started, startErr := startTunnel(ctx, tunnelID, request.Once, serviceUID, serviceGID)
		if startErr != nil {
			return output, startErr
		}
		return started, nil
	case ActionUp:
		return startTunnel(ctx, request.TunnelID, request.Once, serviceUID, serviceGID)
	case ActionStatus:
		arguments := []string{"status", "--json"}
		if request.TunnelID != "" {
			arguments = append(arguments, request.TunnelID)
		}
		return executeController(ctx, arguments...)
	case ActionDown:
		return stopTunnel(ctx, request.TunnelID)
	case ActionRotate, ActionRevoke:
		if _, err := stopTunnel(ctx, request.TunnelID); err != nil {
			return "", err
		}
		return executeController(ctx, request.Action, request.TunnelID)
	default:
		return "", fmt.Errorf("unsupported provisioner action %q", request.Action)
	}
}

func executeEnroll(ctx context.Context, request Request) (string, error) {
	_, _, err := enrollment.ParseClientInvite(request.Invite, time.Now().UTC())
	if err != nil {
		return "", err
	}
	requestRoot := filepath.Join(installlayout.DarwinProvisionerRunRoot, "requests")
	if err := os.MkdirAll(requestRoot, 0o700); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(requestRoot, ".invite-*")
	if err != nil {
		return "", err
	}
	invitePath := temporary.Name()
	defer os.Remove(invitePath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(append(bytes.TrimSpace(request.Invite), '\n')); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	arguments := []string{"enroll", "--yes"}
	if request.PrepareOnly {
		arguments = append(arguments, "--prepare-only")
	}
	if request.ListenPort != 0 {
		arguments = append(arguments, "--listen-port", strconv.Itoa(int(request.ListenPort)))
	}
	if request.RestartPolicy != "" {
		arguments = append(arguments, "--restart", request.RestartPolicy)
	}
	if len(request.Proof) != 0 {
		proofFile, proofErr := os.CreateTemp(requestRoot, ".proof-*")
		if proofErr != nil {
			return "", proofErr
		}
		proofPath := proofFile.Name()
		defer os.Remove(proofPath)
		if proofErr = proofFile.Chmod(0o600); proofErr == nil {
			_, proofErr = proofFile.Write(append(bytes.TrimSpace(request.Proof), '\n'))
		}
		if closeErr := proofFile.Close(); proofErr == nil {
			proofErr = closeErr
		}
		if proofErr != nil {
			return "", proofErr
		}
		arguments = append(arguments, "--proof", proofPath)
	}
	arguments = append(arguments, invitePath)
	return executeController(ctx, arguments...)
}

func startTunnel(ctx context.Context, tunnelID string, once bool, serviceUID, serviceGID uint32) (string, error) {
	if err := config.ValidateTunnelID(tunnelID); err != nil {
		return "", err
	}
	unlock := lockTunnelStart(tunnelID)
	defer unlock()
	store := lifecycle.Store{Root: installlayout.DarwinClientRuntimeRoot}
	label := installlayout.DarwinTunnelLabelPrefix + tunnelID
	job, err := inspectTunnelJob(ctx, label)
	if err != nil {
		return "", err
	}
	if current, readErr := store.Read(tunnelID); readErr == nil &&
		current.Phase == lifecycle.PhaseReady && current.PID > 0 &&
		job.loaded && job.pid == current.PID && processAlive(current.PID) {
		return encodeOutput(map[string]any{"status": "already_ready", "tunnel_id": tunnelID, "pid": current.PID})
	}
	if err := persistDarwinDesiredState(tunnelID, routestate.DesiredRunning); err != nil {
		return "", err
	}
	if err := ensureTunnelRuntime(tunnelID, serviceUID, serviceGID); err != nil {
		return "", err
	}
	plistPath, label, err := writeTunnelPlist(tunnelID, once, false)
	if err != nil {
		return "", err
	}
	if job.loaded {
		if err := runLaunchctl(ctx, "bootout", "system/"+label); err != nil {
			return "", err
		}
	}
	if err := runLaunchctl(ctx, "bootstrap", "system", plistPath); err != nil {
		return "", err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = runLaunchctl(ctx, "bootout", "system/"+label)
		}
	}()
	if err := runLaunchctl(ctx, "kickstart", "-k", "system/"+label); err != nil {
		return "", err
	}
	output, err := waitForTunnelReadiness(ctx, store, label, tunnelID)
	if err != nil {
		return "", err
	}
	rollback = false
	return output, nil
}

func waitForTunnelReadiness(ctx context.Context, store lifecycle.Store, label, tunnelID string) (string, error) {
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		state, readErr := store.Read(tunnelID)
		if readErr == nil && state.Phase == lifecycle.PhaseReady && state.PID > 0 {
			readyJob, inspectErr := inspectTunnelJob(ctx, label)
			if inspectErr != nil {
				return "", inspectErr
			}
			if !readyJob.loaded || readyJob.pid != state.PID || !processAlive(state.PID) {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return encodeOutput(map[string]any{
				"status": "started", "tunnel_id": tunnelID, "phase": state.Phase,
				"pid": state.PID, "listen_endpoint": state.ListenEndpoint,
				"target_health": lifecycle.TargetHealthNotChecked,
			})
		}
		if readErr == nil && state.Phase == lifecycle.PhaseFailed {
			return "", fmt.Errorf("tunnel failed before readiness: %s", state.Error)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", errors.New("timed out waiting for authenticated tunnel readiness")
}

func stopTunnel(ctx context.Context, tunnelID string) (string, error) {
	if err := config.ValidateTunnelID(tunnelID); err != nil {
		return "", err
	}
	if _, _, err := writeTunnelPlist(tunnelID, true, false); err != nil {
		return "", err
	}
	label := installlayout.DarwinTunnelLabelPrefix + tunnelID
	job, err := inspectTunnelJob(ctx, label)
	if err != nil {
		return "", err
	}
	if job.loaded {
		if err := runLaunchctl(ctx, "bootout", "system/"+label); err != nil {
			return "", err
		}
	}
	store := lifecycle.Store{Root: installlayout.DarwinClientRuntimeRoot}
	state, readErr := store.Read(tunnelID)
	if job.pid > 0 {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && processAlive(job.pid) {
			time.Sleep(50 * time.Millisecond)
		}
		if processAlive(job.pid) {
			return "", fmt.Errorf("tunnel process %d remained alive after launchd bootout", job.pid)
		}
	}
	stopped := lifecycle.State{
		TunnelID: tunnelID, Phase: lifecycle.PhaseStopped,
		TargetHealth: lifecycle.TargetHealthNotChecked,
	}
	if readErr != nil {
		stopped.Error = "previous lifecycle state unavailable: " + readErr.Error()
	} else {
		stopped.ListenEndpoint = state.ListenEndpoint
		stopped.Generation = state.Generation
	}
	_ = store.Write(stopped)
	if err := persistDarwinDesiredState(tunnelID, routestate.DesiredStopped); err != nil {
		slog.Error("persist desired stopped state after tunnel stop", "tunnel_id", tunnelID, "err", err)
	}
	return encodeOutput(map[string]any{"status": "stopped", "tunnel_id": tunnelID, "phase": lifecycle.PhaseStopped})
}

func writeTunnelPlist(tunnelID string, once, runAtLoad bool) (string, string, error) {
	contents, label, err := renderTunnelPlist(tunnelID, once, runAtLoad)
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(installlayout.DarwinLaunchDaemonRoot, label+".plist")
	if err := writeAtomic(path, contents, 0o644); err != nil {
		return "", "", err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return "", "", err
	}
	validator := exec.Command("/usr/bin/plutil", "-lint", path)
	validator.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := validator.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("validate generated tunnel LaunchDaemon: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return path, label, nil
}

func persistDarwinDesiredState(tunnelID, desired string) error {
	store := routestate.Store{Root: installlayout.DarwinClientRoutesDirectory}
	exists, err := store.Exists(tunnelID)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	intent, err := store.LoadIntent(tunnelID)
	if err != nil {
		intent = routestate.Intent{
			Kind:          routestate.KindDesiredState,
			SchemaVersion: routestate.CurrentSchemaVersion,
			RouteID:       tunnelID,
			RestartPolicy: routestate.RestartUnlessStopped,
		}
	}
	intent.DesiredState = desired
	if desired == routestate.DesiredRunning && intent.RestartPolicy == routestate.RestartManual {
		intent.BootID = darwinBootID()
	}
	if desired == routestate.DesiredStopped {
		intent.BootID = ""
	}
	return store.WriteIntent(intent)
}

func desiredRunAtLoad(tunnelID string) bool {
	store := routestate.Store{Root: installlayout.DarwinClientRoutesDirectory}
	receipt, err := store.LoadReceipt(tunnelID)
	if err != nil {
		return false
	}
	if receipt.RevokedAt != "" || receipt.AuthorizationNotAfter == "" {
		return false
	}
	notAfter, err := grant.ParseUTC(receipt.AuthorizationNotAfter)
	if err != nil || grant.ReadyToExpire(notAfter, time.Now().UTC()) {
		return false
	}
	intent, err := store.LoadIntent(tunnelID)
	if err != nil {
		return false
	}
	return routestate.ShouldStartAtBoot(intent, darwinBootID())
}

func darwinBootID() string {
	output, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func renderTunnelPlist(tunnelID string, once, runAtLoad bool) ([]byte, string, error) {
	if err := config.ValidateTunnelID(tunnelID); err != nil {
		return nil, "", err
	}
	label := installlayout.DarwinTunnelLabelPrefix + tunnelID
	onceArgument := ""
	if once {
		onceArgument = "<string>--once</string>"
	}
	runAtLoadValue := "<false/>"
	if runAtLoad {
		runAtLoadValue = "<true/>"
	}
	contents := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array>
<string>%s</string><string>run</string><string>--route</string><string>%s</string>%s<string>--managed-lifecycle</string>
</array>
<key>UserName</key><string>%s</string><key>GroupName</key><string>%s</string>
<key>RunAtLoad</key>%s<key>KeepAlive</key><false/>
<key>ThrottleInterval</key><integer>5</integer><key>ProcessType</key><string>Background</string>
</dict></plist>
`, label, installlayout.DarwinControllerPath,
		tunnelID, onceArgument, installlayout.DarwinClientServiceUser, installlayout.DarwinClientServiceGroup,
		runAtLoadValue)
	return []byte(contents), label, nil
}

func ensureTunnelRuntime(tunnelID string, uid, gid uint32) error {
	path := filepath.Join(installlayout.DarwinClientRuntimeRoot, tunnelID)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

var errProvisionerOutputTruncated = errors.New("provisioner child output exceeded limit")

func executeController(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, installlayout.DarwinControllerPath, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &limitedBuffer{buffer: &stdout, limit: MaxResponseBytes / 2}
	command.Stderr = &limitedBuffer{buffer: &stderr, limit: MaxResponseBytes / 2}
	if err := command.Run(); err != nil {
		if errors.Is(err, errProvisionerOutputTruncated) {
			return "", errProvisionerOutputTruncated
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}
	return stdout.String(), nil
}

type limitedBuffer struct {
	buffer *bytes.Buffer
	limit  int
}

func (writer *limitedBuffer) Write(data []byte) (int, error) {
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		return 0, errProvisionerOutputTruncated
	}
	if len(data) > remaining {
		written, _ := writer.buffer.Write(data[:remaining])
		return written, errProvisionerOutputTruncated
	}
	return writer.buffer.Write(data)
}

func runLaunchctl(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "/bin/launchctl", arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w (%s)", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return nil
}

func inspectTunnelJob(ctx context.Context, label string) (tunnelJob, error) {
	if !strings.HasPrefix(label, installlayout.DarwinTunnelLabelPrefix) {
		return tunnelJob{}, errors.New("refusing to inspect a non-WarpTweet launchd label")
	}
	command := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+label)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &limitedBuffer{buffer: &stdout, limit: 64 << 10}
	command.Stderr = &limitedBuffer{buffer: &stderr, limit: 16 << 10}
	err := command.Run()
	if err != nil {
		diagnostic := stderr.String() + stdout.String()
		if strings.Contains(diagnostic, "Could not find service") || strings.Contains(diagnostic, "service not found") {
			return tunnelJob{}, nil
		}
		return tunnelJob{}, fmt.Errorf("inspect launchd job %s: %w (%s)", label, err, strings.TrimSpace(diagnostic))
	}
	return parseTunnelJob(label, stdout.String())
}

func parseTunnelJob(label, output string) (tunnelJob, error) {
	expectedProgram := "program = " + installlayout.DarwinControllerPath
	programMatches := 0
	pid := 0
	pidMatches := 0
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "program = ") {
			programMatches++
			if line != expectedProgram {
				return tunnelJob{}, fmt.Errorf("launchd job %s has unexpected program", label)
			}
		}
		if strings.HasPrefix(line, "pid = ") {
			pidMatches++
			parsed, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid = ")))
			if err != nil || parsed <= 0 {
				return tunnelJob{}, fmt.Errorf("launchd job %s has invalid PID", label)
			}
			pid = parsed
		}
	}
	if programMatches != 1 || pidMatches > 1 {
		return tunnelJob{}, fmt.Errorf("launchd job %s output is not canonical", label)
	}
	return tunnelJob{loaded: true, pid: pid}, nil
}

func ensureSocketDirectory() error {
	if err := os.MkdirAll(installlayout.DarwinProvisionerRunRoot, 0o755); err != nil {
		return err
	}
	if err := os.Chown(installlayout.DarwinProvisionerRunRoot, 0, 0); err != nil {
		return err
	}
	return os.Chmod(installlayout.DarwinProvisionerRunRoot, 0o755)
}

func removeStaleSocket() error {
	info, err := os.Lstat(installlayout.DarwinProvisionerSocket)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 {
		return errors.New("refusing non-root or non-socket provisioner endpoint")
	}
	return os.Remove(installlayout.DarwinProvisionerSocket)
}

func lookupIdentity(userName, groupName string) (uint32, uint32, error) {
	account, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve service user: %w", err)
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve service group: %w", err)
	}
	uid, err := parseID(account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := parseID(group.Gid)
	if err != nil {
		return 0, 0, err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, errors.New("service identity must be non-root")
	}
	return uid, gid, nil
}

func parseID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	return err == nil && process.Signal(syscall.Signal(0)) == nil
}

func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".warptweet-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeResponse(writer io.Writer, response Response) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(response)
}

func encodeOutput(value any) (string, error) {
	var builder strings.Builder
	encoder := json.NewEncoder(&builder)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func enrollOutputTunnelID(output string) string {
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &payload); err != nil {
		return ""
	}
	tunnelID, _ := payload["tunnel_id"].(string)
	return tunnelID
}

var tunnelStartLocks sync.Map

func lockTunnelStart(tunnelID string) func() {
	value, _ := tunnelStartLocks.LoadOrStore(tunnelID, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func reconcileDarwinBoot(ctx context.Context, serviceUID, serviceGID uint32) error {
	store := routestate.Store{Root: installlayout.DarwinClientRoutesDirectory}
	routes, err := store.List()
	if err != nil {
		return err
	}
	bootID := darwinBootID()
	var errs []error
	for _, route := range routes {
		if route.Invalid {
			continue
		}
		if _, _, err := writeTunnelPlist(route.RouteID, true, false); err != nil {
			slog.Error("darwin boot plist failed", "route_id", route.RouteID, "err", err)
			errs = append(errs, fmt.Errorf("route %s plist: %w", route.RouteID, err))
			continue
		}
		if !routestate.ShouldStartAtBoot(route.Intent, bootID) {
			continue
		}
		if _, err := startTunnel(ctx, route.RouteID, true, serviceUID, serviceGID); err != nil {
			slog.Error("darwin boot start failed", "route_id", route.RouteID, "err", err)
		}
	}
	return errors.Join(errs...)
}
