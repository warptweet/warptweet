// Package grant defines host-authoritative service authorization leases.
// Invite lifetime remains a separate 15-minute enrollment window.
package grant

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultAuthorizationDuration is the installed host default grant length.
	DefaultAuthorizationDuration = 30 * 24 * time.Hour
	// DefaultMaximumAuthorizationDuration is the installed host maximum.
	DefaultMaximumAuthorizationDuration = 365 * 24 * time.Hour
	// ImplementationMaximumAuthorizationDuration bounds integer and time limits.
	ImplementationMaximumAuthorizationDuration = 100 * 365 * 24 * time.Hour
	// RFC3339UTC is the exact wire timestamp format for grant facts.
	RFC3339UTC = time.RFC3339Nano
)

// ErrInvalidDuration identifies a duration that must fail closed.
var ErrInvalidDuration = errors.New("invalid authorization duration")

// ParseAccessDuration parses one public CLI duration such as 30d, 24h, 15m, or 30s.
// The result is a whole number of seconds. Floating-point values, mixed units,
// and bare numbers are rejected.
func ParseAccessDuration(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("%w: duration is empty", ErrInvalidDuration)
	}
	if strings.ContainsAny(trimmed, ".eE+/") {
		return 0, fmt.Errorf("%w: fractional or scientific durations are forbidden", ErrInvalidDuration)
	}
	if len(trimmed) < 2 {
		return 0, fmt.Errorf("%w: duration must be an integer followed by d, h, m, or s", ErrInvalidDuration)
	}
	unit := trimmed[len(trimmed)-1]
	number := trimmed[:len(trimmed)-1]
	if number == "" || number[0] == '-' {
		return 0, fmt.Errorf("%w: duration must be a positive integer with a unit", ErrInvalidDuration)
	}
	for _, char := range number {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("%w: duration must be a positive integer with a unit", ErrInvalidDuration)
		}
	}
	quantity, err := strconv.ParseUint(number, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("%w: duration overflows the implementation limit", ErrInvalidDuration)
	}
	if quantity == 0 {
		return 0, fmt.Errorf("%w: duration must be positive", ErrInvalidDuration)
	}
	var unitDuration time.Duration
	switch unit {
	case 'd':
		unitDuration = 24 * time.Hour
	case 'h':
		unitDuration = time.Hour
	case 'm':
		unitDuration = time.Minute
	case 's':
		unitDuration = time.Second
	default:
		return 0, fmt.Errorf("%w: duration unit must be d, h, m, or s", ErrInvalidDuration)
	}
	if quantity > uint64(ImplementationMaximumAuthorizationDuration/unitDuration) {
		return 0, fmt.Errorf("%w: duration overflows the implementation limit", ErrInvalidDuration)
	}
	parsed := time.Duration(quantity) * unitDuration
	if parsed%time.Second != 0 {
		return 0, fmt.Errorf("%w: duration must be a whole number of seconds", ErrInvalidDuration)
	}
	return parsed, nil
}

// Seconds converts a duration to a bounded positive integer second count.
func Seconds(duration time.Duration) (int64, error) {
	if duration <= 0 {
		return 0, fmt.Errorf("%w: duration must be positive", ErrInvalidDuration)
	}
	if duration%time.Second != 0 {
		return 0, fmt.Errorf("%w: duration must be a whole number of seconds", ErrInvalidDuration)
	}
	if duration > ImplementationMaximumAuthorizationDuration {
		return 0, fmt.Errorf("%w: duration overflows the implementation limit", ErrInvalidDuration)
	}
	return int64(duration / time.Second), nil
}

// DurationFromSeconds converts a wire integer into a duration.
func DurationFromSeconds(seconds int64) (time.Duration, error) {
	if seconds <= 0 {
		return 0, fmt.Errorf("%w: duration seconds must be positive", ErrInvalidDuration)
	}
	if seconds > int64(ImplementationMaximumAuthorizationDuration/time.Second) {
		return 0, fmt.Errorf("%w: duration overflows the implementation limit", ErrInvalidDuration)
	}
	return time.Duration(seconds) * time.Second, nil
}

// FormatUTC formats a time as an exact RFC 3339 UTC timestamp.
func FormatUTC(value time.Time) (string, error) {
	if value.IsZero() {
		return "", fmt.Errorf("%w: timestamp is zero", ErrInvalidDuration)
	}
	return value.UTC().Format(RFC3339UTC), nil
}

// ParseUTC parses a host-authoritative RFC 3339 UTC timestamp.
func ParseUTC(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, fmt.Errorf("%w: timestamp is empty", ErrInvalidDuration)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: timestamp must be RFC 3339 UTC: %v", ErrInvalidDuration, err)
		}
	}
	return parsed.UTC(), nil
}

// AuthorizationNotAfter returns accepted_at + duration as an exact UTC timestamp.
func AuthorizationNotAfter(acceptedAt time.Time, durationSeconds int64) (time.Time, string, error) {
	duration, err := DurationFromSeconds(durationSeconds)
	if err != nil {
		return time.Time{}, "", err
	}
	if acceptedAt.IsZero() {
		return time.Time{}, "", fmt.Errorf("%w: accepted_at is zero", ErrInvalidDuration)
	}
	notAfter := acceptedAt.UTC().Add(duration)
	if !notAfter.After(acceptedAt.UTC()) {
		return time.Time{}, "", fmt.Errorf("%w: authorization_not_after overflowed", ErrInvalidDuration)
	}
	encoded, err := FormatUTC(notAfter)
	if err != nil {
		return time.Time{}, "", err
	}
	return notAfter, encoded, nil
}

// OpenSSHExpiryTime formats not-after as OpenSSH expiry-time UTC.
func OpenSSHExpiryTime(notAfter time.Time) (string, error) {
	if notAfter.IsZero() {
		return "", fmt.Errorf("%w: expiry-time is zero", ErrInvalidDuration)
	}
	return notAfter.UTC().Format("20060102150405") + "Z", nil
}
