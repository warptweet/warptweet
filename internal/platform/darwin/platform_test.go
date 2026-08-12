package darwin

import (
	"runtime"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
)

func TestNewRequiresSupportedDarwin(t *testing.T) {
	t.Parallel()

	platform, err := New()
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		if err == nil {
			t.Fatal("New accepted a non-Darwin production host")
		}
		return
	}
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	layout, err := platform.Layout()
	if err != nil {
		t.Fatalf("Layout: %v", err)
	}
	if layout.SSHPath() != installlayout.DarwinSSHPath ||
		layout.ClientManifestPath() != installlayout.DarwinClientManifestPath ||
		layout.ClientRuntimeRoot() != installlayout.DarwinClientRuntimeRoot ||
		layout.ClientServiceUser() != installlayout.DarwinClientServiceUser {
		t.Fatalf("unexpected darwin layout paths: ssh=%q manifest=%q runtime=%q user=%q",
			layout.SSHPath(), layout.ClientManifestPath(), layout.ClientRuntimeRoot(), layout.ClientServiceUser())
	}
}
