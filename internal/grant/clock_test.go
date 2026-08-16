package grant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObserveClockRejectsRollbackAndImplausible(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "clock.json")
	first := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	if _, err := ObserveClock(path, first); err != nil {
		t.Fatalf("ObserveClock first: %v", err)
	}
	if _, err := ObserveClock(path, first.Add(time.Minute)); err != nil {
		t.Fatalf("ObserveClock forward: %v", err)
	}
	if _, err := ObserveClock(path, first.Add(time.Minute).Add(-MaterialRollback)); err != nil {
		t.Fatalf("ObserveClock at MaterialRollback: %v", err)
	}
	if _, err := ObserveClock(path, first.Add(time.Minute).Add(-MaterialRollback/2)); err != nil {
		t.Fatalf("ObserveClock below MaterialRollback: %v", err)
	}
	_, err := ObserveClock(path, first.Add(-time.Hour))
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("rollback err=%v", err)
	}
	if _, err := ObserveClock(path, time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted implausible clock")
	}
}

func TestObserveClockRejectsCorruptObservation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "clock.json")
	if err := os.WriteFile(path, []byte(`{"kind":"warptweet.host-clock-observation","schema_version":1,"last_observed_utc":"2026-08-16T12:00:00Z","extra":true}`+"\n"), 0o600); err != nil {
		t.Fatalf("write unknown: %v", err)
	}
	if _, err := ObserveClock(path, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted unknown field")
	}
	if err := os.WriteFile(path, []byte(`{"kind":"other","schema_version":1,"last_observed_utc":"2026-08-16T12:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write kind: %v", err)
	}
	if _, err := ObserveClock(path, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted wrong kind")
	}
}
