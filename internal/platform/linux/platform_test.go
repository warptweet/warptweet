package linux

import (
	"runtime"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
)

func TestNewRequiresSupportedLinux(t *testing.T) {
	t.Parallel()

	platform, err := New()
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		if err == nil {
			t.Fatal("New accepted a non-Linux production host")
		}
		return
	}
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := platform.RequireSupported(); err != nil {
		t.Fatalf("RequireSupported: %v", err)
	}
	layout, err := platform.Layout()
	if err != nil {
		t.Fatalf("Layout: %v", err)
	}
	if layout.SSHPath() != installlayout.SSHPath ||
		layout.ClientManifestPath() != installlayout.ClientManifestPath ||
		layout.ClientRuntimeRoot() != installlayout.ClientRuntimeRoot {
		t.Fatalf("unexpected linux layout: %+v", layout)
	}
	selected, err := platform.ArtifactProfile()
	if err != nil {
		t.Fatalf("ArtifactProfile: %v", err)
	}
	if string(layout.ArtifactProfileID()) == "" || layout.ArtifactProfileID() != selected.ID {
		t.Fatalf("layout artifact profile ID mismatch: %q vs %q", layout.ArtifactProfileID(), selected.ID)
	}
}
