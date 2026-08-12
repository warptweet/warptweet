// Package artifactprofile defines immutable platform artifact attestation
// profiles. Wire cryptography stays in package profile; this package owns
// executable format, linkage, fixed layout, and support matrix membership.
package artifactprofile

import (
	"fmt"
	"runtime"

	"warptweet.com/warptweet/internal/installlayout"
)

// ID uniquely identifies one reviewed platform artifact contract.
type ID string

const (
	LinuxAMD64  ID = "linux-amd64"
	LinuxARM64  ID = "linux-arm64"
	DarwinAMD64 ID = "darwin-amd64"
	DarwinARM64 ID = "darwin-arm64"
)

// Layout is the fixed production filesystem contract for one artifact profile.
// Paths are installation invariants and are never selected by a .wt manifest.
type Layout struct {
	ControllerPath             string
	ClientManifestPath         string
	ClientIdentityDirectory    string
	ClientIdentityPath         string
	ClientTrustDirectory       string
	ClientKnownHostsPath       string
	ClientGlobalKnownHostsPath string
	ClientRuntimeRoot          string
	ClientServiceUser          string
	ClientServiceGroup         string
	OpenSSHPrefix              string
	SSHPath                    string
	SSHKeygenPath              string
}

// Profile binds one platform and architecture to exact executable attestation
// rules and a fixed filesystem layout.
type Profile struct {
	ID               ID
	GOOS             string
	GOARCH           string
	ExecutableFormat string
	OpenSSLLinkage   string
	Layout           Layout
	Supported        bool
}

var registry = map[ID]Profile{
	LinuxAMD64: {
		ID:               LinuxAMD64,
		GOOS:             "linux",
		GOARCH:           "amd64",
		ExecutableFormat: "ELF",
		OpenSSLLinkage:   "static",
		Layout:           linuxLayout(),
		Supported:        true,
	},
	LinuxARM64: {
		ID:               LinuxARM64,
		GOOS:             "linux",
		GOARCH:           "arm64",
		ExecutableFormat: "ELF",
		OpenSSLLinkage:   "static",
		Layout:           linuxLayout(),
		Supported:        true,
	},
	DarwinAMD64: {
		ID:               DarwinAMD64,
		GOOS:             "darwin",
		GOARCH:           "amd64",
		ExecutableFormat: "Mach-O",
		OpenSSLLinkage:   "static",
		Layout:           darwinLayout(),
		Supported:        true,
	},
	DarwinARM64: {
		ID:               DarwinARM64,
		GOOS:             "darwin",
		GOARCH:           "arm64",
		ExecutableFormat: "Mach-O",
		OpenSSLLinkage:   "static",
		Layout:           darwinLayout(),
		Supported:        true,
	},
}

func linuxLayout() Layout {
	return Layout{
		ControllerPath:             installlayout.ControllerPath,
		ClientManifestPath:         installlayout.ClientManifestPath,
		ClientIdentityDirectory:    installlayout.ClientIdentityDirectory,
		ClientIdentityPath:         installlayout.ClientIdentityPath,
		ClientTrustDirectory:       installlayout.ClientTrustDirectory,
		ClientKnownHostsPath:       installlayout.ClientKnownHostsPath,
		ClientGlobalKnownHostsPath: installlayout.ClientGlobalKnownHostsPath,
		ClientRuntimeRoot:          installlayout.ClientRuntimeRoot,
		ClientServiceUser:          installlayout.ClientServiceUser,
		ClientServiceGroup:         installlayout.ClientServiceGroup,
		OpenSSHPrefix:              installlayout.OpenSSHPrefix,
		SSHPath:                    installlayout.SSHPath,
		SSHKeygenPath:              installlayout.SSHKeygenPath,
	}
}

func darwinLayout() Layout {
	return Layout{
		ControllerPath:             installlayout.DarwinControllerPath,
		ClientManifestPath:         installlayout.DarwinClientManifestPath,
		ClientIdentityDirectory:    installlayout.DarwinClientIdentityDirectory,
		ClientIdentityPath:         installlayout.DarwinClientIdentityPath,
		ClientTrustDirectory:       installlayout.DarwinClientTrustDirectory,
		ClientKnownHostsPath:       installlayout.DarwinClientKnownHostsPath,
		ClientGlobalKnownHostsPath: installlayout.DarwinClientGlobalKnownHostsPath,
		ClientRuntimeRoot:          installlayout.DarwinClientRuntimeRoot,
		ClientServiceUser:          installlayout.DarwinClientServiceUser,
		ClientServiceGroup:         installlayout.DarwinClientServiceGroup,
		OpenSSHPrefix:              installlayout.DarwinOpenSSHPrefix,
		SSHPath:                    installlayout.DarwinSSHPath,
		SSHKeygenPath:              installlayout.DarwinSSHKeygenPath,
	}
}

// Lookup returns a defensive copy of a registered artifact profile.
func Lookup(id ID) (Profile, error) {
	selected, ok := registry[id]
	if !ok {
		return Profile{}, fmt.Errorf("unsupported platform artifact profile %q", id)
	}
	return selected, nil
}

// CurrentID returns the artifact-profile ID for the running GOOS/GOARCH pair.
func CurrentID() (ID, error) {
	switch {
	case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
		return LinuxAMD64, nil
	case runtime.GOOS == "linux" && runtime.GOARCH == "arm64":
		return LinuxARM64, nil
	case runtime.GOOS == "darwin" && runtime.GOARCH == "amd64":
		return DarwinAMD64, nil
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return DarwinARM64, nil
	default:
		return "", fmt.Errorf(
			"unsupported platform artifact profile for %s/%s",
			runtime.GOOS,
			runtime.GOARCH,
		)
	}
}

// Current returns the artifact profile for the running platform when it is a
// supported production target.
func Current() (Profile, error) {
	id, err := CurrentID()
	if err != nil {
		return Profile{}, err
	}
	selected, err := Lookup(id)
	if err != nil {
		return Profile{}, err
	}
	if !selected.Supported {
		return Profile{}, fmt.Errorf(
			"platform artifact profile %q is not supported for production client preflight",
			selected.ID,
		)
	}
	return selected, nil
}
