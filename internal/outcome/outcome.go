package outcome

import (
	"encoding/json"
	"errors"
	"flag"
	"strings"
)

const (
	CodeUsage                   = "usage"
	CodeHelp                    = "help"
	CodePreflightFailed         = "preflight_failed"
	CodeEngineMissing           = "engine_missing"
	CodeHostBusy                = "host_busy"
	CodeStaleState              = "stale_state"
	CodeLocalPortConflict       = "local_port_conflict"
	CodeHostUnreachable         = "host_unreachable"
	CodeInviteExpired           = "invite_expired"
	CodeInviteConsumedRetryable = "invite_consumed_retryable"
	CodeInviteConsumed          = "invite_consumed"
	CodeInviteMismatch          = "invite_mismatch"
	CodeEnrolledNotReady        = "enrolled_not_ready"
	CodeProvisionerUnavailable  = "provisioner_unavailable"
	CodeClockBlocked            = "clock_blocked"
	CodePackageBoundary         = "package_boundary"
	CodeFailed                  = "failed"
)

var (
	ErrHostBusy               = errors.New(CodeHostBusy)
	ErrProvisionerUnavailable = errors.New(CodeProvisionerUnavailable)
	ErrPackageBoundary        = errors.New(CodePackageBoundary)
	ErrLocalPortConflict      = errors.New(CodeLocalPortConflict)
	ErrEngineMissing          = errors.New(CodeEngineMissing)
	ErrClockBlocked           = errors.New(CodeClockBlocked)
	ErrInviteExpired          = errors.New(CodeInviteExpired)
	ErrEnrolledNotReady       = errors.New(CodeEnrolledNotReady)
)

// Error is the public operator-contract failure type.
type Error struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Hint        string `json:"hint,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	exit        int
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	return err.Message
}

func (err *Error) ExitCode() int {
	if err == nil {
		return 1
	}
	return err.exit
}

// Object is the public JSON failure document.
func (err *Error) Object() map[string]any {
	if err == nil {
		return map[string]any{
			"version": 1,
			"ok":      false,
			"error": map[string]any{
				"code":    CodeFailed,
				"message": "internal error",
			},
		}
	}
	errorObject := map[string]any{
		"code":    err.Code,
		"message": err.Message,
	}
	if err.Hint != "" {
		errorObject["hint"] = err.Hint
	}
	if err.Replacement != "" {
		errorObject["replacement"] = err.Replacement
	}
	return map[string]any{
		"version": 1,
		"ok":      false,
		"error":   errorObject,
	}
}

func Usage(message string) *Error {
	return &Error{Code: CodeUsage, Message: message, Hint: "Run warptweet --help", exit: 2}
}

func Help() *Error {
	return &Error{Code: CodeHelp, Message: "", exit: 0}
}

func Replaced(retired, replacement string) *Error {
	return &Error{
		Code:        CodeUsage,
		Message:     retired + " was replaced by '" + replacement + "'",
		Hint:        "Run " + replacement,
		Replacement: replacement,
		exit:        2,
	}
}

func New(code, message, hint string, exit int) *Error {
	if exit == 0 {
		exit = 1
	}
	return &Error{Code: code, Message: message, Hint: hint, exit: exit}
}

// From classifies any error into the public contract.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	if errors.Is(err, flag.ErrHelp) {
		return Help()
	}
	message := strings.TrimSpace(err.Error())
	switch {
	case errors.Is(err, ErrHostBusy):
		return New(CodeHostBusy, message, "Retry after the other host command exits", 1)
	case errors.Is(err, ErrProvisionerUnavailable):
		return New(CodeProvisionerUnavailable, message, "Start or reinstall the client package so the provisioner socket exists", 1)
	case errors.Is(err, ErrPackageBoundary):
		return New(CodePackageBoundary, message, "Repair the package-owned layout", 1)
	case errors.Is(err, ErrLocalPortConflict):
		return New(CodeLocalPortConflict, message, "Run warptweet down <route>, or pass --listen-port N", 1)
	case errors.Is(err, ErrEngineMissing):
		return New(CodeEngineMissing, message, "Reinstall the WarpTweet package", 1)
	case errors.Is(err, ErrClockBlocked):
		return New(CodeClockBlocked, message, "Run host clock recovery before minting invites", 1)
	case errors.Is(err, ErrInviteExpired):
		return New(CodeInviteExpired, message, "Ask the host for a new invite", 1)
	case errors.Is(err, ErrEnrolledNotReady):
		return New(CodeEnrolledNotReady, message, "Run warptweet repair <route>", 1)
	case strings.Contains(message, "host_busy") || strings.Contains(message, "resource is busy"):
		return New(CodeHostBusy, message, "Retry after the other host command exits", 1)
	case strings.Contains(message, "provisioner_unavailable"):
		return New(CodeProvisionerUnavailable, message, "Start or reinstall the client package so the provisioner socket exists", 1)
	case strings.Contains(message, "package_boundary"):
		return New(CodePackageBoundary, message, "Repair the package-owned layout", 1)
	case strings.Contains(message, "local_port_conflict") || strings.Contains(message, "listen port"):
		return New(CodeLocalPortConflict, message, "Run warptweet down <route>, or pass --listen-port N", 1)
	case strings.Contains(message, "engine_missing") || strings.Contains(message, "bundled ssh-keygen is required"):
		return New(CodeEngineMissing, message, "Reinstall the WarpTweet package", 1)
	case strings.Contains(message, "clock") && strings.Contains(message, "blocked"):
		return New(CodeClockBlocked, message, "Run host clock recovery before minting invites", 1)
	case strings.Contains(message, "invite") && strings.Contains(message, "expired"):
		return New(CodeInviteExpired, message, "Ask the host for a new invite", 1)
	case strings.Contains(message, "enrolled") && strings.Contains(message, "not ready"):
		return New(CodeEnrolledNotReady, message, "Run warptweet repair <route>", 1)
	case strings.Contains(message, "flag provided") ||
		strings.Contains(message, "may be specified only once") ||
		strings.Contains(message, "unexpected positional") ||
		strings.Contains(message, "requires exactly") ||
		strings.Contains(message, "unknown command") ||
		strings.HasPrefix(message, "host --"):
		return Usage(message)
	default:
		return New(CodeFailed, message, "", 1)
	}
}

// Encode writes one JSON object for --json failures.
func Encode(raw *Error) ([]byte, error) {
	if raw == nil {
		raw = New(CodeFailed, "internal error", "", 1)
	}
	return json.Marshal(raw.Object())
}
