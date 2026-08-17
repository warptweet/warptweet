package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"warptweet.com/warptweet/internal/routestate"
)

func runConnect(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	flags := newFlagSet("connect", stderr)
	yes := onceBoolFlag{name: "--yes"}
	proofPath := onceStringFlag{name: "--proof"}
	once := onceBoolFlag{name: "--once"}
	restart := onceStringFlag{name: "--restart"}
	listenPort := onceStringFlag{name: "--listen-port"}
	flags.Var(&yes, "yes", "skip interactive confirmation")
	flags.Var(&proofPath, "proof", "path to server enrollment proof JSON")
	flags.Var(&once, "once", "do not restart after exit when bringing the tunnel up")
	flags.Var(&restart, "restart", "durable restart policy: unless-stopped or manual")
	flags.Var(&listenPort, "listen-port", "loopback listen port (default 15432)")
	positionals, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("connect requires exactly one invite file path")
	}
	invitePath := positionals[0]
	if strings.TrimSpace(invitePath) == "" {
		return errors.New("connect requires exactly one invite file path")
	}

	restartPolicy, err := routestate.ParseRestartPolicy(restart.value)
	if err != nil {
		return err
	}
	var port uint16
	if listenPort.value != "" {
		parsed, err := strconv.ParseUint(listenPort.value, 10, 16)
		if err != nil || parsed == 0 {
			return errors.New("listen-port must be a nonzero TCP port")
		}
		port = uint16(parsed)
	}

	enrollArgs := buildConnectEnrollArgs(invitePath, yes.value, proofPath.value, port, restartPolicy)

	// Capture enroll JSON on a buffer; interactive prompts use user-facing stdout.
	var enrollOut strings.Builder
	if err := runEnroll(ctx, enrollArgs, &enrollOut, stdout); err != nil {
		return err
	}

	tunnelID, listenEndpoint, serviceEndpoint, err := parseEnrollConnectFields(enrollOut.String())
	if err != nil {
		return err
	}
	upArgs := buildConnectUpArgs(tunnelID, once.value)
	var upOut strings.Builder
	if err := runUp(ctx, upArgs, &upOut, stderr, dependencies); err != nil {
		fmt.Fprintf(stdout, "enrolled_not_ready\nopen     %s\ntunnel   %s\nerror    %v\n", listenEndpoint, tunnelID, err)
		return fmt.Errorf("enrolled as %s but not ready: %w", tunnelID, err)
	}

	if serviceEndpoint != "" {
		_, err = fmt.Fprintf(stdout, "connected\nopen     %s\nservice  %s\ntunnel   %s\n", listenEndpoint, serviceEndpoint, tunnelID)
	} else {
		_, err = fmt.Fprintf(stdout, "connected\nopen     %s\ntunnel   %s\n", listenEndpoint, tunnelID)
	}
	return err
}

func buildConnectEnrollArgs(invitePath string, yes bool, proofPath string, listenPort uint16, restartPolicy string) []string {
	var args []string
	if listenPort != 0 {
		args = append(args, "--listen-port", strconv.Itoa(int(listenPort)))
	}
	args = append(args, "--restart", restartPolicy)
	if yes {
		args = append(args, "--yes")
	}
	if proofPath != "" {
		args = append(args, "--proof", proofPath)
	}
	return append(args, invitePath)
}

func buildConnectUpArgs(tunnelID string, once bool) []string {
	// Flags before the tunnel id positional.
	var args []string
	if once {
		args = append(args, "--once")
	}
	return append(args, tunnelID)
}

func parseEnrollConnectFields(enrollJSON string) (tunnelID, listenEndpoint, serviceEndpoint string, err error) {
	enrollJSON = strings.TrimSpace(enrollJSON)
	if enrollJSON == "" {
		return "", "", "", errors.New("enroll produced no output")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(enrollJSON), &payload); err != nil {
		return "", "", "", fmt.Errorf("parse enroll output: %w", err)
	}
	tunnelID, _ = payload["tunnel_id"].(string)
	listenEndpoint, _ = payload["listen_endpoint"].(string)
	serviceEndpoint, _ = payload["service_endpoint"].(string)
	if tunnelID == "" || listenEndpoint == "" {
		return "", "", "", errors.New("enroll output missing tunnel_id or listen_endpoint")
	}
	return tunnelID, listenEndpoint, serviceEndpoint, nil
}
