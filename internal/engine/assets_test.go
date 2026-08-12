package engine

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateAssetsWithDependenciesAcceptsExactCompositePin(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	report, err := validateAssetsWithDependencies(state.spec, state.dependencies)
	if err != nil {
		t.Fatalf("validateAssetsWithDependencies: %v", err)
	}
	if report.HostKeyPins != 1 || report.HostKeyAlias != "warptweet-database-primary" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestValidateAssetsWithDependenciesRejectsRemovedPathAuthority(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ClientSpec){
		"identity": func(spec *ClientSpec) {
			spec.IdentityFile = filepath.Join(filepath.Dir(spec.IdentityFile), "alternate")
		},
		"known hosts": func(spec *ClientSpec) {
			spec.KnownHostsFile = filepath.Join(filepath.Dir(spec.KnownHostsFile), "alternate")
		},
		"global known hosts": func(spec *ClientSpec) {
			spec.GlobalKnownHostsFile = filepath.Join(filepath.Dir(spec.GlobalKnownHostsFile), "alternate")
		},
	}
	for name, mutate := range tests {
		name := name
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := newClientAssetTestState(t)
			mutate(&state.spec)
			if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
				t.Fatal("validation accepted caller-selected client asset path")
			}
		})
	}
}

func TestValidateAssetsWithDependenciesRejectsClassicalPinForAlias(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	contents := "warptweet-database-primary ssh-ed25519 " + testPublicKeyBlob("ssh-ed25519") + " warptweet-managed-host\n"
	writeClientAssetTestFile(t, state.spec.KnownHostsFile, []byte(contents))
	if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
		t.Fatal("validation accepted a classical-only host pin")
	}
}

func TestValidateAssetsWithDependenciesRejectsWildcardTrust(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	contents := "* " + state.spec.Profile.AuthenticationKeyType + " " +
		testPublicKeyBlob(state.spec.Profile.AuthenticationKeyType) + " warptweet-managed-host\n"
	writeClientAssetTestFile(t, state.spec.KnownHostsFile, []byte(contents))
	if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
		t.Fatal("validation accepted wildcard host trust")
	}
}

func TestValidateAssetsWithDependenciesRejectsMismatchedBlobType(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	contents := "warptweet-database-primary " + state.spec.Profile.AuthenticationKeyType + " " +
		testPublicKeyBlob("ssh-ed25519") + " warptweet-managed-host\n"
	writeClientAssetTestFile(t, state.spec.KnownHostsFile, []byte(contents))
	if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
		t.Fatal("validation accepted an algorithm-confused key blob")
	}
}

func TestValidateAssetsWithDependenciesRejectsNonemptyGlobalTrust(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	writeClientAssetTestFile(t, state.spec.GlobalKnownHostsFile, []byte("unexpected trust\n"))
	if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
		t.Fatal("validation accepted a nonempty global trust store")
	}
}

func TestValidateAssetsWithDependenciesRejectsUnmanagedOrNonCanonicalPins(t *testing.T) {
	t.Parallel()

	tests := map[string]func(ClientSpec) string{
		"missing managed marker": func(spec ClientSpec) string {
			return "warptweet-database-primary " + spec.Profile.AuthenticationKeyType + " " +
				testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + "\n"
		},
		"alternate comment": func(spec ClientSpec) string {
			return "warptweet-database-primary " + spec.Profile.AuthenticationKeyType + " " +
				testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + " operator-comment\n"
		},
		"multiple aliases": func(spec ClientSpec) string {
			return "warptweet-database-primary,warptweet-other " + spec.Profile.AuthenticationKeyType + " " +
				testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + " warptweet-managed-host\n"
		},
		"repeated whitespace": func(spec ClientSpec) string {
			return "warptweet-database-primary  " + spec.Profile.AuthenticationKeyType + " " +
				testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + " warptweet-managed-host\n"
		},
		"blank line": func(spec ClientSpec) string {
			return "\nwarptweet-database-primary " + spec.Profile.AuthenticationKeyType + " " +
				testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + " warptweet-managed-host\n"
		},
		"missing final LF": func(spec ClientSpec) string {
			return "warptweet-database-primary " + spec.Profile.AuthenticationKeyType + " " +
				testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + " warptweet-managed-host"
		},
	}
	for name, contents := range tests {
		name := name
		contents := contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := newClientAssetTestState(t)
			writeClientAssetTestFile(t, state.spec.KnownHostsFile, []byte(contents(state.spec)))
			if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
				t.Fatal("validation accepted an unmanaged or non-canonical pin")
			}
		})
	}
}

func TestValidateAssetsWithDependenciesRejectsFilesystemAuthorityViolations(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*clientAssetTestState){
		"group writable identity": func(state *clientAssetTestState) {
			if err := os.Chmod(state.spec.IdentityFile, 0o460); err != nil {
				state.t.Fatalf("Chmod: %v", err)
			}
		},
		"writable trust ancestor": func(state *clientAssetTestState) {
			if err := os.Chmod(state.layout.trustDirectory, 0o770); err != nil {
				state.t.Fatalf("Chmod: %v", err)
			}
		},
		"non-root file owner": func(state *clientAssetTestState) {
			state.wrapMetadata(func(path string, metadata *clientFileMetadata) {
				if path == state.spec.IdentityFile {
					metadata.uid = state.identity.uid
				}
			})
		},
		"wrong file group": func(state *clientAssetTestState) {
			state.wrapMetadata(func(path string, metadata *clientFileMetadata) {
				if path == state.spec.KnownHostsFile {
					metadata.gid = 0
				}
			})
		},
		"access ACL": func(state *clientAssetTestState) {
			state.wrapMetadata(func(path string, metadata *clientFileMetadata) {
				if path == state.spec.KnownHostsFile {
					metadata.hasAccessACL = true
				}
			})
		},
		"default ancestor ACL": func(state *clientAssetTestState) {
			state.wrapMetadata(func(path string, metadata *clientFileMetadata) {
				if path == state.layout.trustDirectory {
					metadata.hasDefaultACL = true
				}
			})
		},
		"hard-linked identity": func(state *clientAssetTestState) {
			state.wrapMetadata(func(path string, metadata *clientFileMetadata) {
				if path == state.spec.IdentityFile {
					metadata.linkCount = 2
				}
			})
		},
	}
	for name, mutate := range tests {
		name := name
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := newClientAssetTestState(t)
			mutate(&state)
			if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
				t.Fatal("validation accepted a filesystem authority violation")
			}
		})
	}
}

func TestValidateAssetsWithDependenciesRejectsSymlinkedAsset(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	target := filepath.Join(filepath.Dir(state.spec.KnownHostsFile), "alternate")
	writeClientAssetTestFile(t, target, []byte(validClientPin(state.spec)))
	if err := os.Remove(state.spec.KnownHostsFile); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(target, state.spec.KnownHostsFile); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
		t.Fatal("validation accepted a symlinked known-hosts file")
	}
}

func TestValidateAssetsWithDependenciesRejectsSubstitutionBetweenChecks(t *testing.T) {
	t.Parallel()

	for _, phase := range []string{"after initial open", "before final verify"} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			state := newClientAssetTestState(t)
			replacement := filepath.Join(state.layout.trustDirectory, "replacement")
			writeClientAssetTestFile(t, replacement, []byte(validClientPin(state.spec)))
			substitute := func() {
				if err := os.Rename(replacement, state.spec.KnownHostsFile); err != nil {
					t.Errorf("Rename: %v", err)
				}
			}
			if phase == "after initial open" {
				state.dependencies.hooks.afterInitialOpen = substitute
			} else {
				state.dependencies.hooks.beforeFinalVerify = substitute
			}
			if _, err := validateAssetsWithDependencies(state.spec, state.dependencies); err == nil {
				t.Fatal("validation accepted a substituted known-hosts file")
			}
		})
	}
}

type clientAssetTestState struct {
	t            *testing.T
	spec         ClientSpec
	layout       clientStateLayout
	identity     clientServiceIdentity
	dependencies clientAssetDependencies
}

// assetSpec is retained as the shared launch-test fixture. Production asset
// validation itself is exercised through the explicit dependency seam above.
func assetSpec(t *testing.T) ClientSpec {
	t.Helper()
	return newClientAssetTestState(t).spec
}

func newClientAssetTestState(t *testing.T) clientAssetTestState {
	t.Helper()

	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	base := filepath.Join(etc, "warptweet")
	identityDirectory := filepath.Join(base, "identity")
	trustDirectory := filepath.Join(base, "trust")
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{
		{path: root, mode: 0o755},
		{path: etc, mode: 0o755},
		{path: base, mode: 0o755},
		{path: identityDirectory, mode: 0o750},
		{path: trustDirectory, mode: 0o750},
	} {
		path, mode := entry.path, entry.mode
		if path != root {
			if err := os.Mkdir(path, mode); err != nil {
				t.Fatalf("Mkdir %q: %v", path, err)
			}
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod %q: %v", path, err)
		}
	}

	layout := clientStateLayout{
		rootPath:             root,
		manifestPath:         filepath.Join(base, "client.wt"),
		identityDirectory:    identityDirectory,
		identityPath:         filepath.Join(identityDirectory, "client"),
		trustDirectory:       trustDirectory,
		knownHostsPath:       filepath.Join(trustDirectory, "known_hosts"),
		globalKnownHostsPath: filepath.Join(trustDirectory, "known_hosts.empty"),
		serviceUser:          "test-client",
		serviceGroup:         "test-client",
		directoryPolicies: map[string]clientNodePolicy{
			root: {
				description: "test root",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			etc: {
				description: "test etc",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			base: {
				description: "test client-state directory",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			identityDirectory: {
				description: "test identity directory",
				directory:   true,
				mode:        0o750,
				group:       clientNodeServiceGroup,
			},
			trustDirectory: {
				description: "test trust directory",
				directory:   true,
				mode:        0o750,
				group:       clientNodeServiceGroup,
			},
		},
	}
	identity := clientServiceIdentity{uid: 1234, gid: 2345}
	spec := validClientSpec(t)
	spec.IdentityFile = layout.identityPath
	spec.KnownHostsFile = layout.knownHostsPath
	spec.GlobalKnownHostsFile = layout.globalKnownHostsPath
	writeClientAssetTestFile(t, spec.IdentityFile, []byte("opaque test identity"))
	writeClientAssetTestFile(t, spec.KnownHostsFile, []byte(validClientPin(spec)))
	writeClientAssetTestFile(t, spec.GlobalKnownHostsFile, nil)

	serviceGroupPaths := map[string]bool{
		layout.manifestPath:         true,
		layout.identityDirectory:    true,
		layout.identityPath:         true,
		layout.trustDirectory:       true,
		layout.knownHostsPath:       true,
		layout.globalKnownHostsPath: true,
	}
	dependencies := clientAssetDependencies{
		layout: layout,
		resolveServiceIdentity: func(userName, groupName string) (clientServiceIdentity, error) {
			if userName != layout.serviceUser || groupName != layout.serviceGroup {
				return clientServiceIdentity{}, errors.New("unexpected service identity names")
			}
			return identity, nil
		},
		inspectMetadata: func(path string, _ *os.File, _ os.FileInfo) (clientFileMetadata, error) {
			metadata := clientFileMetadata{uid: 0, linkCount: 1}
			if serviceGroupPaths[path] {
				metadata.gid = identity.gid
			}
			return metadata, nil
		},
	}
	return clientAssetTestState{
		t:            t,
		spec:         spec,
		layout:       layout,
		identity:     identity,
		dependencies: dependencies,
	}
}

func (state *clientAssetTestState) wrapMetadata(
	mutate func(string, *clientFileMetadata),
) {
	state.t.Helper()
	base := state.dependencies.inspectMetadata
	state.dependencies.inspectMetadata = func(
		path string,
		file *os.File,
		info os.FileInfo,
	) (clientFileMetadata, error) {
		metadata, err := base(path, file, info)
		if err == nil {
			mutate(path, &metadata)
		}
		return metadata, err
	}
}

func validClientPin(spec ClientSpec) string {
	return "warptweet-database-primary " + spec.Profile.AuthenticationKeyType + " " +
		testPublicKeyBlob(spec.Profile.AuthenticationKeyType) + " warptweet-managed-host\n"
}

func writeClientAssetTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatalf("Chmod writable %q: %v", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat %q: %v", path, err)
	}
	if err := os.WriteFile(path, contents, 0o640); err != nil {
		t.Fatalf("WriteFile %q: %v", path, err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatalf("Chmod %q: %v", path, err)
	}
}

func testPublicKeyBlob(algorithm string) string {
	name := []byte(algorithm)
	const rawKeyBytes = 1344
	blob := make([]byte, 4+len(name)+4+rawKeyBytes)
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], rawKeyBytes)
	blob[len(blob)-1] = 1
	return base64.StdEncoding.EncodeToString(blob)
}
