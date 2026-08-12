package artifactprofile

import (
	"runtime"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
)

func TestLinuxArtifactProfilesMatchInstallLayout(t *testing.T) {
	t.Parallel()

	for _, id := range []ID{LinuxAMD64, LinuxARM64} {
		id := id
		t.Run(string(id), func(t *testing.T) {
			t.Parallel()
			selected, err := Lookup(id)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if !selected.Supported ||
				selected.ExecutableFormat != "ELF" ||
				selected.OpenSSLLinkage != "static" ||
				selected.Layout.SSHPath != installlayout.SSHPath ||
				selected.Layout.ClientManifestPath != installlayout.ClientManifestPath ||
				selected.Layout.ClientIdentityPath != installlayout.ClientIdentityPath ||
				selected.Layout.ClientKnownHostsPath != installlayout.ClientKnownHostsPath ||
				selected.Layout.ClientGlobalKnownHostsPath != installlayout.ClientGlobalKnownHostsPath ||
				selected.Layout.ClientRuntimeRoot != installlayout.ClientRuntimeRoot ||
				selected.Layout.ClientServiceUser != installlayout.ClientServiceUser {
				t.Fatalf("unexpected linux artifact profile: %+v", selected)
			}
		})
	}
}

func TestDarwinArtifactProfilesMatchInstallLayout(t *testing.T) {
	t.Parallel()

	for _, id := range []ID{DarwinAMD64, DarwinARM64} {
		id := id
		t.Run(string(id), func(t *testing.T) {
			t.Parallel()
			selected, err := Lookup(id)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if !selected.Supported ||
				selected.ExecutableFormat != "Mach-O" ||
				selected.OpenSSLLinkage != "static" ||
				selected.Layout.SSHPath != installlayout.DarwinSSHPath ||
				selected.Layout.ClientManifestPath != installlayout.DarwinClientManifestPath ||
				selected.Layout.ClientIdentityPath != installlayout.DarwinClientIdentityPath ||
				selected.Layout.ClientKnownHostsPath != installlayout.DarwinClientKnownHostsPath ||
				selected.Layout.ClientGlobalKnownHostsPath != installlayout.DarwinClientGlobalKnownHostsPath ||
				selected.Layout.ClientRuntimeRoot != installlayout.DarwinClientRuntimeRoot ||
				selected.Layout.ClientServiceUser != installlayout.DarwinClientServiceUser {
				t.Fatalf("unexpected darwin artifact profile: %+v", selected)
			}
		})
	}
}

func TestLookupRejectsUnknownArtifactProfile(t *testing.T) {
	t.Parallel()

	if _, err := Lookup("windows-amd64"); err == nil {
		t.Fatal("Lookup accepted an unregistered artifact profile")
	}
}

func TestCurrentMatchesRuntimeWhenSupported(t *testing.T) {
	t.Parallel()

	id, idErr := CurrentID()
	selected, err := Current()
	switch {
	case runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"):
		if idErr != nil || err != nil {
			t.Fatalf("CurrentID/Current: %v / %v", idErr, err)
		}
		if selected.ID != id || !selected.Supported {
			t.Fatalf("unexpected current profile: id=%s selected=%+v", id, selected)
		}
	case runtime.GOOS == "darwin" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"):
		if idErr != nil || err != nil {
			t.Fatalf("CurrentID/Current: %v / %v", idErr, err)
		}
		if selected.ID != id || !selected.Supported || selected.ExecutableFormat != "Mach-O" {
			t.Fatalf("unexpected current darwin profile: id=%s selected=%+v", id, selected)
		}
	default:
		if idErr == nil || err == nil {
			t.Fatal("Current accepted an unlisted platform")
		}
	}
}
