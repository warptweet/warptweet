//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/routestate"
)

type Server struct {
	mu sync.Mutex
}

func (server *Server) Serve(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("provisioner serve requires root")
	}
	if _, _, err := lookupIdentity(installlayout.ClientServiceUser, installlayout.ClientServiceGroup); err != nil {
		return err
	}
	operatorGroup, err := user.LookupGroup(installlayout.LinuxOperatorGroup)
	if err != nil {
		return fmt.Errorf("resolve %s group: %w", installlayout.LinuxOperatorGroup, err)
	}
	operatorGID, err := parseID(operatorGroup.Gid)
	if err != nil {
		return fmt.Errorf("parse %s gid: %w", installlayout.LinuxOperatorGroup, err)
	}
	if err := os.MkdirAll(installlayout.LinuxProvisionerRunRoot, 0o755); err != nil {
		return err
	}
	if err := requireRootOwnedDirectory(installlayout.LinuxProvisionerRunRoot, 0o755); err != nil {
		return err
	}
	if err := removeRootOwnedUnixSocket(installlayout.LinuxProvisionerSocket); err != nil {
		return err
	}
	address := &net.UnixAddr{Name: installlayout.LinuxProvisionerSocket, Net: "unix"}
	oldMask := syscall.Umask(0o077)
	listener, err := net.ListenUnix("unix", address)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listen on provisioner socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(installlayout.LinuxProvisionerSocket)
	if err := os.Chown(installlayout.LinuxProvisionerSocket, 0, int(operatorGID)); err != nil {
		return fmt.Errorf("set provisioner socket ownership: %w", err)
	}
	if err := os.Chmod(installlayout.LinuxProvisionerSocket, 0o660); err != nil {
		return fmt.Errorf("set provisioner socket mode: %w", err)
	}

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
		go server.handleConnection(ctx, connection)
	}
}

func (server *Server) handleConnection(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(90 * time.Second))
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
	requestCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	output, err := executeRequest(requestCtx, request)
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		writeResponse(connection, Response{Error: err.Error()})
		return
	}
	writeResponse(connection, Response{OK: true, Output: output})
}

func executeRequest(ctx context.Context, request Request) (string, error) {
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
		return projectTunnel(ctx, tunnelID, true)
	case ActionStatus:
		arguments := []string{"status", "--json"}
		if request.TunnelID != "" {
			arguments = append(arguments, request.TunnelID)
		}
		return executeController(ctx, arguments...)
	case ActionDown:
		return projectTunnel(ctx, request.TunnelID, false)
	case ActionRotate, ActionRevoke:
		if _, err := projectTunnel(ctx, request.TunnelID, false); err != nil {
			return "", err
		}
		return executeController(ctx, request.Action, request.TunnelID)
	default:
		if isTunnelStartAction(request.Action) {
			return projectTunnel(ctx, request.TunnelID, true)
		}
		return "", fmt.Errorf("unsupported provisioner action %q", request.Action)
	}
}

func executeEnroll(ctx context.Context, request Request) (string, error) {
	if _, _, err := enrollment.ParseClientInvite(request.Invite, time.Now().UTC()); err != nil {
		return "", err
	}
	requestRoot := enrollRequestRoot(installlayout.LinuxProvisionerRunRoot)
	invitePath, proofPath, err := materializeEnrollInputs(requestRoot, request)
	if err != nil {
		return "", err
	}
	defer os.Remove(invitePath)
	if proofPath != "" {
		defer os.Remove(proofPath)
	}
	return executeController(ctx, enrollControllerArgs(invitePath, proofPath, request)...)
}

func projectTunnel(ctx context.Context, routeID string, start bool) (string, error) {
	if err := config.ValidateTunnelID(routeID); err != nil {
		return "", err
	}
	if err := routestate.ValidateRouteID(routeID); err != nil {
		return "", err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", fmt.Errorf("%w: systemctl is required to project warptweet-tunnel@%s", outcome.ErrPackageBoundary, routeID)
	}
	unit := "warptweet-tunnel@" + routeID + ".service"
	action := "stop"
	status := "stopped"
	if start {
		action = "start"
		status = "started"
	}
	cmd := exec.CommandContext(ctx, "systemctl", action, unit)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := runBoundedCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w (%s)", action, unit, err, output)
	}
	return encodeOutput(map[string]any{"status": status, "tunnel_id": routeID, "unit": unit})
}

func executeController(ctx context.Context, arguments ...string) (string, error) {
	cmd := exec.CommandContext(ctx, installlayout.ControllerPath, arguments...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := runBoundedCommand(cmd)
	if err != nil {
		if errors.Is(err, errProvisionerOutputTruncated) {
			return "", err
		}
		if output == "" {
			return "", err
		}
		return "", errors.New(output)
	}
	return output, nil
}

func runBoundedCommand(command *exec.Cmd) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &limitedBuffer{buffer: &stdout, limit: MaxResponseBytes / 2}
	command.Stderr = &limitedBuffer{buffer: &stderr, limit: MaxResponseBytes / 2}
	err := command.Run()
	if errors.Is(err, errProvisionerOutputTruncated) {
		return "", errProvisionerOutputTruncated
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message == "" {
			return "", err
		}
		return message, err
	}
	return stdout.String(), nil
}

func requireRootOwnedDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a directory", path)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s must have mode %04o", path, mode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("%s must be root-owned", path)
	}
	return nil
}

func removeRootOwnedUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a unix socket", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("%s must be a root-owned unix socket", path)
	}
	return os.Remove(path)
}

func enrollOutputTunnelID(output string) string {
	var payload map[string]any
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return ""
	}
	value, _ := payload["tunnel_id"].(string)
	return value
}

func encodeOutput(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(append(raw, '\n')), nil
}

func writeResponse(connection net.Conn, response Response) {
	encoder := json.NewEncoder(connection)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(response)
}

func lookupIdentity(userName, groupName string) (uint32, uint32, error) {
	account, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %s: %w", userName, err)
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %s: %w", groupName, err)
	}
	uid, err := parseID(account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := parseID(group.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func parseID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse id %q: %w", value, err)
	}
	return uint32(parsed), nil
}
