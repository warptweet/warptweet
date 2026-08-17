package grant

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	// BlockedClockKind is the durable host blocked-clock document.
	BlockedClockKind = "warptweet.host-blocked-clock"
	// BlockedClockSchemaVersion is the only accepted blocked-clock schema.
	BlockedClockSchemaVersion = 1
)

// BlockedClock is persisted when the host clock is untrusted.
type BlockedClock struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
	Reason        string `json:"reason"`
	BlockedAt     string `json:"blocked_at"`
}

// LoadBlockedClock reads a blocked-clock document if present.
func LoadBlockedClock(path string) (BlockedClock, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return BlockedClock{}, err
	}
	var blocked BlockedClock
	if err := json.Unmarshal(contents, &blocked); err != nil {
		return BlockedClock{}, fmt.Errorf("%w: blocked clock: %v", ErrInvalidClock, err)
	}
	if blocked.Kind != BlockedClockKind || blocked.SchemaVersion != BlockedClockSchemaVersion {
		return BlockedClock{}, fmt.Errorf("%w: unsupported blocked-clock schema", ErrInvalidClock)
	}
	return blocked, nil
}

// WriteBlockedClock persists a visible blocked-clock state.
func WriteBlockedClock(path, reason string, now time.Time) error {
	encoded, err := FormatUTC(now.UTC())
	if err != nil {
		encoded = now.UTC().Format(RFC3339UTC)
	}
	blocked := BlockedClock{
		Kind:          BlockedClockKind,
		SchemaVersion: BlockedClockSchemaVersion,
		Reason:        reason,
		BlockedAt:     encoded,
	}
	contents, err := json.Marshal(blocked)
	if err != nil {
		return err
	}
	return writeAtomic(path, append(contents, '\n'), 0o700, 0o600, ".wt-blocked-*")
}

// ClearBlockedClock removes a recovered blocked-clock document.
func ClearBlockedClock(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ClockIsBlocked reports whether the host is in blocked-clock state.
func ClockIsBlocked(path string) bool {
	_, err := LoadBlockedClock(path)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}
