package lifecycle

import (
	"os"
	"path/filepath"
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
