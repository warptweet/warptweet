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
	// ClockKind is the durable last-observed host clock document.
	ClockKind = "warptweet.host-clock-observation"
	// ClockSchemaVersion is the only accepted clock observation schema.
	ClockSchemaVersion = 1
	// MaterialRollback is the smallest backward jump treated as unsafe.
	MaterialRollback = time.Second
	maxClockBytes    = 4 << 10
)

// ErrInvalidClock identifies an implausible or rolled-back host clock.
var ErrInvalidClock = errors.New("host clock is invalid")

// ClockObservation is the last host-authoritative wall time persisted on disk.
type ClockObservation struct {
	Kind            string `json:"kind"`
	SchemaVersion   int    `json:"schema_version"`
	LastObservedUTC string `json:"last_observed_utc"`
}

// ObserveClock records now after rejecting a material rollback.
func ObserveClock(path string, now time.Time) (ClockObservation, error) {
	if now.IsZero() {
		return ClockObservation{}, fmt.Errorf("%w: current time is zero", ErrInvalidClock)
	}
	now = now.UTC()
	if now.Year() < 2020 || now.Year() > 2200 {
		return ClockObservation{}, fmt.Errorf("%w: current time %s is implausible", ErrInvalidClock, now.Format(RFC3339UTC))
	}
	existing, err := loadClockObservation(path)
	if err != nil && !os.IsNotExist(err) {
		return ClockObservation{}, err
	}
	if err == nil {
		previous, parseErr := ParseUTC(existing.LastObservedUTC)
		if parseErr != nil {
			return ClockObservation{}, fmt.Errorf("%w: stored observation: %v", ErrInvalidClock, parseErr)
		}
		if now.Add(MaterialRollback).Before(previous) {
			return ClockObservation{}, fmt.Errorf("%w: wall clock rolled back from %s to %s", ErrInvalidClock, existing.LastObservedUTC, now.Format(RFC3339UTC))
		}
	}
	encoded, err := FormatUTC(now)
	if err != nil {
		return ClockObservation{}, err
	}
	observation := ClockObservation{
		Kind:            ClockKind,
		SchemaVersion:   ClockSchemaVersion,
		LastObservedUTC: encoded,
	}
	if err := writeClockObservation(path, observation); err != nil {
		return ClockObservation{}, err
	}
	return observation, nil
}

func loadClockObservation(path string) (ClockObservation, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return ClockObservation{}, err
	}
	if len(contents) == 0 || len(contents) > maxClockBytes {
		return ClockObservation{}, fmt.Errorf("%w: clock observation is empty or oversized", ErrInvalidClock)
	}
	if err := strictjson.RejectDuplicateObjectNames(contents); err != nil {
		return ClockObservation{}, fmt.Errorf("%w: %v", ErrInvalidClock, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var observation ClockObservation
	if err := decoder.Decode(&observation); err != nil {
		return ClockObservation{}, fmt.Errorf("%w: %v", ErrInvalidClock, err)
	}
	if decoder.More() {
		return ClockObservation{}, fmt.Errorf("%w: trailing JSON values", ErrInvalidClock)
	}
	if observation.Kind != ClockKind || observation.SchemaVersion != ClockSchemaVersion {
		return ClockObservation{}, fmt.Errorf("%w: unsupported clock observation schema", ErrInvalidClock)
	}
	return observation, nil
}

func writeClockObservation(path string, observation ClockObservation) error {
	contents, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return writeAtomic(path, contents, 0o700, 0o600, ".wt-clock-*")
}
