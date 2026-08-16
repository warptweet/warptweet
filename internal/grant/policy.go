package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// PolicyKind is the host authorization policy document kind.
	PolicyKind = "warptweet.host-authorization-policy"
	// PolicySchemaVersion is the only accepted policy schema.
	PolicySchemaVersion = 1
	maxPolicyBytes      = 8 << 10
)

// ErrInvalidPolicy identifies a host policy that must fail closed.
var ErrInvalidPolicy = errors.New("invalid host authorization policy")

// Policy is the host-authoritative duration configuration.
type Policy struct {
	Kind                                string `json:"kind"`
	SchemaVersion                       int    `json:"schema_version"`
	DefaultAuthorizationDurationSeconds int64  `json:"default_authorization_duration_seconds"`
	MaximumAuthorizationDurationSeconds int64  `json:"maximum_authorization_duration_seconds"`
}

// InstalledDefault returns the shipped 30-day default and 365-day maximum.
func InstalledDefault() Policy {
	return Policy{
		Kind:                                PolicyKind,
		SchemaVersion:                       PolicySchemaVersion,
		DefaultAuthorizationDurationSeconds: int64(DefaultAuthorizationDuration / time.Second),
		MaximumAuthorizationDurationSeconds: int64(DefaultMaximumAuthorizationDuration / time.Second),
	}
}

// Validate checks that both durations are finite, positive, and ordered.
func Validate(policy Policy) error {
	if policy.Kind != PolicyKind || policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("%w: unsupported kind or schema", ErrInvalidPolicy)
	}
	if _, err := DurationFromSeconds(policy.DefaultAuthorizationDurationSeconds); err != nil {
		return fmt.Errorf("%w: default_authorization_duration_seconds: %v", ErrInvalidPolicy, err)
	}
	if _, err := DurationFromSeconds(policy.MaximumAuthorizationDurationSeconds); err != nil {
		return fmt.Errorf("%w: maximum_authorization_duration_seconds: %v", ErrInvalidPolicy, err)
	}
	if policy.MaximumAuthorizationDurationSeconds < policy.DefaultAuthorizationDurationSeconds {
		return fmt.Errorf("%w: maximum must be at least the default", ErrInvalidPolicy)
	}
	return nil
}

// ResolveDuration returns the grant duration in seconds. A zero request uses
// the default. A request above the maximum is rejected rather than clamped.
func ResolveDuration(policy Policy, requestedSeconds int64) (int64, error) {
	if err := Validate(policy); err != nil {
		return 0, err
	}
	seconds := requestedSeconds
	if seconds == 0 {
		seconds = policy.DefaultAuthorizationDurationSeconds
	}
	if seconds <= 0 {
		return 0, fmt.Errorf("%w: duration must be positive", ErrInvalidDuration)
	}
	if seconds > policy.MaximumAuthorizationDurationSeconds {
		return 0, fmt.Errorf("%w: duration exceeds host maximum of %d seconds", ErrInvalidDuration, policy.MaximumAuthorizationDurationSeconds)
	}
	if _, err := DurationFromSeconds(seconds); err != nil {
		return 0, err
	}
	return seconds, nil
}

// LoadPolicy reads a policy file or returns the installed default when absent.
func LoadPolicy(path string) (Policy, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return InstalledDefault(), nil
		}
		return Policy{}, err
	}
	if len(contents) == 0 || len(contents) > maxPolicyBytes {
		return Policy{}, fmt.Errorf("%w: policy file is empty or exceeds %d bytes", ErrInvalidPolicy, maxPolicyBytes)
	}
	if err := strictjson.RejectDuplicateObjectNames(contents); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if decoder.More() {
		return Policy{}, fmt.Errorf("%w: trailing JSON values", ErrInvalidPolicy)
	}
	if err := Validate(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// WritePolicy persists a validated policy atomically.
func WritePolicy(path string, policy Policy) error {
	if err := Validate(policy); err != nil {
		return err
	}
	contents, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return writeAtomic(path, contents, 0o755, 0o644, ".wt-host-policy-*")
}
