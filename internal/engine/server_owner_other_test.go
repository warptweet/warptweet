//go:build !linux

package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionServerOwnershipFailsClosedOutsideLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset")
	if err := os.WriteFile(path, []byte("asset\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := requireProductionRootOwner(path, info); err == nil {
		t.Fatal("production ownership validation accepted a non-Linux platform")
	}
	if err := requireProductionRootGroupOwner(path, info); err == nil {
		t.Fatal("production root:root ownership validation accepted a non-Linux platform")
	}
	if _, err := inspectProductionServerAccounts("warptweet"); err == nil {
		t.Fatal("production account validation accepted a non-Linux platform")
	}
}
