//go:build !unix

package enrollment

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLockPathExclusiveReclaimsClosedSamePID(t *testing.T) {
	dir := t.TempDir()
	name := "reclaim.lock"
	lockPath := filepath.Join(dir, name)
	// Closed lock file still containing this process's PID must not block
	// acquisition: PID is not a reusable stale-lock identity.
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockPathExclusive(dir, name, "reclaim")
	if err != nil {
		t.Fatalf("reclaim closed same-PID lock: %v", err)
	}
	unlock()
}
