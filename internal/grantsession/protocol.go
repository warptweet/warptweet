// Package grantsession is the host grant-to-process authority. OpenSSH
// registers a verified key over a fixed Unix socket. The authority takes the
// peer PID from kernel credentials, never from caller-supplied data.
package grantsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// Kind is the durable session record kind.
	Kind = "warptweet.grant-session"
	// SchemaVersion is the only accepted session schema.
	SchemaVersion = 1
	// ProtocolVersion is the only accepted socket protocol.
	ProtocolVersion = 1
	// ActionRegister is sent after verified public-key authentication.
	ActionRegister = "register"
	// ActionUnregister is sent on normal disconnect cleanup.
	ActionUnregister = "unregister"
	MaxRequestBytes  = 4 << 10
	MaxResponseBytes = 2 << 10
)

// ErrRejected identifies a registration that must fail closed.
var ErrRejected = errors.New("grant session registration rejected")

var errIdentityGone = errors.New("grant session process identity is gone")

const maxConnectionIDBytes = 96

// Request is the bounded socket request from sshd-session.
type Request struct {
	Version    int    `json:"version"`
	Action     string `json:"action"`
	KeySHA256  string `json:"key_sha256,omitempty"`
	Connection string `json:"connection_id,omitempty"`
}

// Response is the bounded socket response.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ValidateRequest checks one socket request.
func ValidateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol version %d", ErrRejected, request.Version)
	}
	switch request.Action {
	case ActionRegister:
		if len(request.KeySHA256) != 64 || !isLowerHex(request.KeySHA256) {
			return fmt.Errorf("%w: key_sha256 must be 64 lowercase hex characters", ErrRejected)
		}
	case ActionUnregister:
	default:
		return fmt.Errorf("%w: unsupported action %q", ErrRejected, request.Action)
	}
	if request.Connection != "" && !validConnectionID(request.Connection) {
		return fmt.Errorf("%w: connection_id is empty, oversized, or contains disallowed characters", ErrRejected)
	}
	return nil
}

func validConnectionID(value string) bool {
	if value == "" || len(value) > maxConnectionIDBytes {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func decodeRequest(raw []byte) (Request, error) {
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return Request{}, fmt.Errorf("%w: request is empty or oversized", ErrRejected)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if decoder.More() {
		return Request{}, fmt.Errorf("%w: trailing JSON values", ErrRejected)
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func encodeResponse(response Response) []byte {
	raw, err := json.Marshal(response)
	if err != nil {
		return []byte(`{"ok":false,"error":"encode"}` + "\n")
	}
	return append(raw, '\n')
}

func readBounded(reader io.Reader, maximum int) ([]byte, error) {
	limited := &io.LimitedReader{R: reader, N: int64(maximum) + 1}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(raw) > maximum {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrRejected, maximum)
	}
	return raw, nil
}

func isLowerHex(value string) bool {
	if strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
