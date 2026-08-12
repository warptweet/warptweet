// Package platform defines client platform seams used by production preflight.
// Implementations live under platform-specific packages or engine adapters.
// Dependency injection remains per invocation; this package has no mutable
// global test hooks.
package platform

import (
	"os"

	"warptweet.com/warptweet/internal/artifactprofile"
)

// ExecutableInspector attests one opened executable against the selected
// artifact profile's format and linkage rules.
type ExecutableInspector interface {
	Inspect(file *os.File) error
}

// OwnershipChecker validates filesystem ownership policy for fixed layout nodes.
type OwnershipChecker interface {
	OwnedByRoot(info os.FileInfo) (bool, error)
	OwnedByEffectiveUser(info os.FileInfo) (bool, error)
}

// ServiceIdentity describes the dedicated client service account shape.
type ServiceIdentity struct {
	User  string
	Group string
	UID   uint32
	GID   uint32
}

// ServiceIdentityResolver resolves and validates the dedicated service account.
type ServiceIdentityResolver interface {
	Resolve(user, group string) (ServiceIdentity, error)
}

// ClientStateInspector opens and attests fixed client-state paths.
type ClientStateInspector interface {
	RequireSupported() error
}

// ACLValidator rejects disallowed ACL and extended-attribute state.
type ACLValidator interface {
	RequireSupported() error
}

// RuntimeDirectoryManager attests readiness runtime directories.
type RuntimeDirectoryManager interface {
	RuntimeRoot() string
}

// Layout exposes the fixed installation paths for one artifact profile.
type Layout interface {
	ArtifactProfileID() artifactprofile.ID
	SSHPath() string
	ClientManifestPath() string
	ClientIdentityPath() string
	ClientKnownHostsPath() string
	ClientGlobalKnownHostsPath() string
	ClientRuntimeRoot() string
	ClientServiceUser() string
	ClientServiceGroup() string
}

// ClientPlatform is the production attestation surface for one OS/architecture.
// Wire cryptographic policy is not part of this interface.
type ClientPlatform interface {
	ArtifactProfile() (artifactprofile.Profile, error)
	RequireSupported() error
	Layout() (Layout, error)
}
