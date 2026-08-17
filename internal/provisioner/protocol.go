// Package provisioner defines the narrow local privilege boundary used by the
// installed macOS client. It never accepts shell text, executable paths,
// OpenSSH options, or launchd fragments.
package provisioner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/installlayout"
)

const (
	ProtocolVersion  = 1
	MaxRequestBytes  = 1 << 20
	MaxResponseBytes = 1 << 20

	ActionEnroll  = "enroll"
	ActionConnect = "connect"
	ActionUp      = "up"
	ActionStatus  = "status"
	ActionDown    = "down"
	ActionRotate  = "rotate"
	ActionRevoke  = "revoke"
)

type Request struct {
	Version       int             `json:"version"`
	Action        string          `json:"action"`
	Invite        json.RawMessage `json:"invite,omitempty"`
	Proof         json.RawMessage `json:"proof,omitempty"`
	TunnelID      string          `json:"tunnel_id,omitempty"`
	ListenPort    uint16          `json:"listen_port,omitempty"`
	RestartPolicy string          `json:"restart_policy,omitempty"`
	PrepareOnly   bool            `json:"prepare_only,omitempty"`
	Once          bool            `json:"once,omitempty"`
}

type Response struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func ValidateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf("unsupported provisioner protocol version %d", request.Version)
	}
	switch request.Action {
	case ActionEnroll, ActionConnect:
		if len(request.Invite) == 0 || len(request.Invite) > MaxRequestBytes {
			return errors.New("enroll requires a bounded invite document")
		}
		if request.TunnelID != "" {
			return errors.New("enroll tunnel_id is derived from the invite")
		}
		if request.Once && request.Action != ActionConnect {
			return errors.New("once is valid only for up or connect")
		}
		if len(request.Proof) > MaxRequestBytes {
			return errors.New("enrollment proof exceeds the request limit")
		}
		if request.RestartPolicy != "" && request.RestartPolicy != "unless-stopped" && request.RestartPolicy != "manual" {
			return errors.New("restart_policy must be unless-stopped or manual")
		}
	case ActionStatus:
		if len(request.Invite) != 0 || len(request.Proof) != 0 || request.Once || request.ListenPort != 0 || request.PrepareOnly {
			return errors.New("status contains fields for another action")
		}
		if request.TunnelID != "" {
			if err := config.ValidateTunnelID(request.TunnelID); err != nil {
				return err
			}
		}
	case ActionUp, ActionDown, ActionRotate, ActionRevoke:
		if len(request.Invite) != 0 {
			return errors.New("only enroll may carry an invite document")
		}
		if len(request.Proof) != 0 || request.ListenPort != 0 || request.PrepareOnly {
			return errors.New("request contains fields for another action")
		}
		if err := config.ValidateTunnelID(request.TunnelID); err != nil {
			return err
		}
		if request.Once && request.Action != ActionUp {
			return errors.New("once is valid only for up")
		}
	default:
		return fmt.Errorf("unsupported provisioner action %q", request.Action)
	}
	return nil
}

func Call(ctx context.Context, request Request) (Response, error) {
	if err := ValidateRequest(request); err != nil {
		return Response{}, err
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", installlayout.DarwinProvisionerSocket)
	if err != nil {
		return Response{}, fmt.Errorf("connect to installed WarpTweet provisioner: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(60 * time.Second)
	_ = connection.SetDeadline(deadline)
	encoder := json.NewEncoder(connection)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(request); err != nil {
		return Response{}, fmt.Errorf("send provisioner request: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return Response{}, errors.New("provisioner connection is not a Unix socket")
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return Response{}, fmt.Errorf("finish provisioner request: %w", err)
	}
	var response Response
	if err := decodeSingleJSON(connection, MaxResponseBytes, &response); err != nil {
		return Response{}, fmt.Errorf("read provisioner response: %w", err)
	}
	if !response.OK {
		response.Error = safeRemoteError(response.Error)
		return response, errors.New(response.Error)
	}
	response.Output = sanitizeRemoteText(response.Output)
	return response, nil
}

func decodeSingleJSON(reader io.Reader, maximum int64, destination any) error {
	limited := &io.LimitedReader{R: reader, N: maximum + 1}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(raw)) > maximum {
		return fmt.Errorf("JSON document exceeds %d bytes", maximum)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON document contains a trailing value")
		}
		return fmt.Errorf("decode trailing JSON data: %w", err)
	}
	return nil
}

func safeRemoteError(message string) string {
	message = sanitizeRemoteText(message)
	if message == "" {
		return "provisioner request failed"
	}
	return message
}

func sanitizeRemoteText(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	var builder strings.Builder
	for _, character := range message {
		if character == '\n' || character == '\r' || character == '\t' || character < 0x20 || character == 0x7f {
			builder.WriteByte(' ')
			continue
		}
		builder.WriteRune(character)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}
