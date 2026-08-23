//go:build darwin

package engine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
)

type clientNodeTestFileInfo struct {
	mode os.FileMode
	size int64
	dir  bool
}

func (info clientNodeTestFileInfo) Name() string       { return "node" }
func (info clientNodeTestFileInfo) Size() int64        { return info.size }
func (info clientNodeTestFileInfo) Mode() os.FileMode  { return info.mode }
func (info clientNodeTestFileInfo) ModTime() time.Time { return time.Time{} }
func (info clientNodeTestFileInfo) IsDir() bool        { return info.dir }
func (info clientNodeTestFileInfo) Sys() any           { return nil }

func TestValidateClientNodeRejectsDarwinRootAdminRegularFile(t *testing.T) {
	t.Parallel()

	err := validateClientNode(
		clientNodeTestFileInfo{mode: 0o440, size: 32},
		clientFileMetadata{uid: 0, gid: 80, linkCount: 1},
		clientNodePolicy{
			description: "client root-group file",
			mode:        0o440,
			group:       clientNodeRootGroup,
			minimumSize: 1,
			maximumSize: 64,
		},
		clientServiceIdentity{uid: 920, gid: 920},
	)
	if err == nil || !strings.Contains(err.Error(), "ownership is 0:80, want 0:0") {
		t.Fatalf("validateClientNode error = %v, want root:admin regular-file rejection", err)
	}
}

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
		strings.Contains(message, "invalid signature") ||
		strings.Contains(message, "SHA-256 mismatch") ||
		strings.Contains(message, "no such file") ||
		strings.Contains(message, "not provisioned") ||
		strings.Contains(message, "inspect fixed OpenSSH ancestor") ||
		strings.Contains(message, "permission denied") ||
		strings.Contains(message, "stat ")) {
		t.Fatalf("Preflight error = %v, want unprovisioned Darwin package rejection", err)
	}
}

func TestProductionClientStateValidationFailsClosedWithoutDarwinServiceIdentity(t *testing.T) {
	t.Parallel()

	_, err := LoadProductionClientManifest(installlayout.DarwinClientManifestPath)
	if err == nil {
		// A fully provisioned local package (e.g. interop lab) is a valid host
		// state; the fail-closed path is only required when package state is absent.
		return
	}
	if !(strings.Contains(err.Error(), "not provisioned") ||
		strings.Contains(err.Error(), "no such file") ||
		strings.Contains(err.Error(), "permission denied") ||
		strings.Contains(err.Error(), installlayout.DarwinClientManifestPath) ||
		strings.Contains(err.Error(), "ownership") ||
		strings.Contains(err.Error(), "service identity") ||
		strings.Contains(err.Error(), "requires cgo")) {
		t.Fatalf("LoadProductionClientManifest error = %v, want unprovisioned rejection", err)
	}
}
