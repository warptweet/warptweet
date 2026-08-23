package lifecycle

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestStoreWriteReadAndLock(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	lock, err := store.Lock("database-primary")
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer Unlock(lock)

	if _, err := store.Lock("database-primary"); err == nil {
		t.Fatal("second lock should fail")
	}
	admin, err := store.AdminLock("database-primary")
	if err != nil {
		t.Fatalf("AdminLock during runtime lock: %v", err)
	}
	if _, err := store.AdminLock("database-primary"); err == nil {
		t.Fatal("second admin lock should fail")
	}
	Unlock(admin)

	if err := store.Write(State{
		TunnelID:       "database-primary",
		Phase:          PhaseReady,
		PID:            os.Getpid(),
		ListenEndpoint: "127.0.0.1:15432",
		Generation:     "g1",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	state, err := store.Read("database-primary")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if state.Phase != PhaseReady || state.ListenEndpoint != "127.0.0.1:15432" ||
		state.TargetHealth != TargetHealthNotChecked || state.PID != os.Getpid() {
		t.Fatalf("unexpected state: %+v", state)
	}
	if _, err := os.Stat(filepath.Join(store.Root, "database-primary", "state.json")); err != nil {
		t.Fatalf("state file missing: %v", err)
	}
}

func TestValidateTunnelID(t *testing.T) {
	t.Parallel()

	if err := validateTunnelID("database-primary"); err != nil {
		t.Fatal(err)
	}
	if err := validateTunnelID("../etc"); err == nil {
		t.Fatal("accepted path traversal")
	}
	if err := validateTunnelID(""); err == nil {
		t.Fatal("accepted empty id")
	}
}

func TestReadMarksMissingProcessFailed(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.Write(State{
		TunnelID: "gone",
		Phase:    PhaseReady,
		PID:      1 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	state, err := store.Read("gone")
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != PhaseFailed {
		t.Fatalf("phase=%s, want Failed", state.Phase)
	}
	if state.Error != "process is not running" {
		t.Fatalf("error=%q", state.Error)
	}
}

func TestReadRejectsPIDReuse(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.Write(State{
		TunnelID: "live",
		Phase:    PhaseReady,
		PID:      os.Getpid(),
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root, "live", "state.json")
	// Force a start identity that cannot match this process.
	replaced := []byte(`{"tunnel_id":"live","phase":"Ready","pid":` + strconv.Itoa(os.Getpid()) + `,"start_identity":1,"target_health":"not_checked","updated_at":"2026-08-23T00:00:00Z"}`)
	if err := os.WriteFile(path, replaced, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := store.Read("live")
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != PhaseFailed {
		t.Fatalf("phase=%s, want Failed after start-identity mismatch", state.Phase)
	}
}

func TestReadMissingIsStopped(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	state, err := store.Read("missing-tunnel")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if state.Phase != PhaseStopped {
		t.Fatalf("phase=%s", state.Phase)
	}
}
