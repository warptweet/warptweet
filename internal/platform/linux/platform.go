// Package linux implements the supported Linux client artifact profiles.
package linux

import (
	"fmt"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/platform"
)

// Platform is the production Linux client attestation surface.
type Platform struct {
	profile artifactprofile.Profile
}

// New returns the Linux client platform for the running architecture when the
// corresponding artifact profile is supported.
func New() (Platform, error) {
	selected, err := artifactprofile.Current()
	if err != nil {
		return Platform{}, err
	}
	if selected.GOOS != "linux" {
		return Platform{}, fmt.Errorf("linux platform adapter received artifact profile %q", selected.ID)
	}
	return Platform{profile: selected}, nil
}

// ArtifactProfile returns the immutable Linux artifact profile.
func (platform Platform) ArtifactProfile() (artifactprofile.Profile, error) {
	if platform.profile.ID == "" {
		return artifactprofile.Profile{}, fmt.Errorf("linux platform adapter is uninitialized")
	}
	return platform.profile, nil
}

// RequireSupported fails closed when the Linux artifact profile is unavailable.
func (platform Platform) RequireSupported() error {
	_, err := platform.ArtifactProfile()
	return err
}

// Layout returns the fixed Linux installation layout.
func (platform Platform) Layout() (platform.Layout, error) {
	selected, err := platform.ArtifactProfile()
	if err != nil {
		return nil, err
	}
	return layout{profile: selected}, nil
}

type layout struct {
	profile artifactprofile.Profile
}

func (value layout) ArtifactProfileID() artifactprofile.ID {
	return value.profile.ID
}

func (value layout) SSHPath() string {
	return value.profile.Layout.SSHPath
}

func (value layout) ClientManifestPath() string {
	return value.profile.Layout.ClientManifestPath
}

func (value layout) ClientIdentityPath() string {
	return value.profile.Layout.ClientIdentityPath
}

func (value layout) ClientKnownHostsPath() string {
	return value.profile.Layout.ClientKnownHostsPath
}

func (value layout) ClientGlobalKnownHostsPath() string {
	return value.profile.Layout.ClientGlobalKnownHostsPath
}

func (value layout) ClientRuntimeRoot() string {
	return value.profile.Layout.ClientRuntimeRoot
}

func (value layout) ClientServiceUser() string {
	return value.profile.Layout.ClientServiceUser
}

func (value layout) ClientServiceGroup() string {
	return value.profile.Layout.ClientServiceGroup
}
