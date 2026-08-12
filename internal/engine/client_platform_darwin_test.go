//go:build darwin

package engine

import (
	"context"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
)

func TestProductionClientPreflightFailsClosedWithoutInstalledDarwinPackage(t *testing.T) {
	t.Parallel()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	_, err = Preflight(context.Background(), Binary{
		Path:   installlayout.DarwinSSHPath,
		SHA256: strings.Repeat("0", 64),
	}, selected)
	if err == nil {
		t.Fatal("Preflight unexpectedly succeeded without an installed Darwin package")
	}
	// Unprovisioned machines must fail before any network activity. Accept the
	// first durable package gate: missing path, ownership, codesign Team ID, or
	// service identity.
	message := err.Error()
	if !(strings.Contains(message, "code-signing Team ID") ||
		strings.Contains(message, "no such file") ||
		strings.Contains(message, "not provisioned") ||
		strings.Contains(message, "inspect fixed OpenSSH ancestor") ||
		strings.Contains(message, "stat ")) {
		t.Fatalf("Preflight error = %v, want unprovisioned Darwin package rejection", err)
	}
}

func TestProductionClientStateValidationFailsClosedWithoutDarwinServiceIdentity(t *testing.T) {
	t.Parallel()

	_, err := LoadProductionClientManifest(installlayout.DarwinClientManifestPath)
	if err == nil {
		t.Fatal("LoadProductionClientManifest unexpectedly succeeded without package state")
	}
	if !(strings.Contains(err.Error(), "not provisioned") ||
		strings.Contains(err.Error(), "no such file") ||
		strings.Contains(err.Error(), installlayout.DarwinClientManifestPath)) {
		t.Fatalf("LoadProductionClientManifest error = %v, want unprovisioned rejection", err)
	}
}
