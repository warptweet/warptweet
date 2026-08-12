package engine

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/profile"
)

func TestProductionClientStateLayoutUsesOnlyFixedInstallPaths(t *testing.T) {
	t.Parallel()

	layout := productionClientStateLayout()
	linux := linuxProductionClientStateLayout()
	darwin := darwinProductionClientStateLayout()
	if layout.rootPath != "/" {
		t.Fatalf("production client-state root = %q, want /", layout.rootPath)
	}
	switch {
	case layout.manifestPath == linux.manifestPath:
		if layout.identityDirectory != linux.identityDirectory ||
			layout.identityPath != linux.identityPath ||
			layout.trustDirectory != linux.trustDirectory ||
			layout.knownHostsPath != linux.knownHostsPath ||
			layout.globalKnownHostsPath != linux.globalKnownHostsPath ||
			layout.serviceUser != linux.serviceUser ||
			layout.serviceGroup != linux.serviceGroup {
			t.Fatalf("production linux client-state layout diverged: %+v", layout)
		}
	case layout.manifestPath == darwin.manifestPath:
		if layout.identityDirectory != darwin.identityDirectory ||
			layout.identityPath != darwin.identityPath ||
			layout.trustDirectory != darwin.trustDirectory ||
			layout.knownHostsPath != darwin.knownHostsPath ||
			layout.globalKnownHostsPath != darwin.globalKnownHostsPath ||
			layout.serviceUser != darwin.serviceUser ||
			layout.serviceGroup != darwin.serviceGroup {
			t.Fatalf("production darwin client-state layout diverged: %+v", layout)
		}
	default:
		t.Fatalf("production client-state layout is neither linux nor darwin: %+v", layout)
	}
	for _, path := range []string{
		layout.rootPath,
		layout.identityDirectory,
		layout.trustDirectory,
	} {
		if _, ok := layout.directoryPolicies[path]; !ok {
			t.Errorf("missing directory policy for %q", path)
		}
	}
}

func TestLoadProductionClientManifestWithDependenciesAcceptsProtectedManifest(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	writeClientAssetTestFile(t, state.layout.manifestPath, validClientManifestV3(t))
	manifest, err := loadProductionClientManifestWithDependencies(
		state.layout.manifestPath,
		state.dependencies,
	)
	if err != nil {
		t.Fatalf("loadProductionClientManifestWithDependencies: %v", err)
	}
	if manifest.SchemaVersion != config.CurrentSchemaVersion ||
		manifest.Kind != config.ClientTunnelsKind ||
		manifest.Tunnels[0].ID != "database-primary" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestLoadProductionClientManifestWithDependenciesRejectsCallerSelectedPath(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	alternate := filepath.Join(filepath.Dir(state.layout.manifestPath), "alternate.wt")
	writeClientAssetTestFile(t, alternate, validClientManifestV3(t))
	_, err := loadProductionClientManifestWithDependencies(alternate, state.dependencies)
	if err == nil || !strings.Contains(err.Error(), state.layout.manifestPath) {
		t.Fatalf("error = %v, want exact fixed manifest path rejection", err)
	}
}

func TestLoadProductionClientManifestWithDependenciesRejectsSubstitution(t *testing.T) {
	t.Parallel()

	state := newClientAssetTestState(t)
	writeClientAssetTestFile(t, state.layout.manifestPath, validClientManifestV3(t))
	replacement := filepath.Join(filepath.Dir(state.layout.manifestPath), "replacement.wt")
	writeClientAssetTestFile(t, replacement, validClientManifestV3(t))
	state.dependencies.hooks.afterInitialOpen = func() {
		if err := os.Rename(replacement, state.layout.manifestPath); err != nil {
			t.Errorf("Rename: %v", err)
		}
	}
	if _, err := loadProductionClientManifestWithDependencies(
		state.layout.manifestPath,
		state.dependencies,
	); err == nil {
		t.Fatal("production loader accepted a substituted manifest")
	}
}

func TestLoadProductionClientManifestWithDependenciesRejectsInvalidServiceIdentity(t *testing.T) {
	t.Parallel()

	for name, identity := range map[string]clientServiceIdentity{
		"root user":  {uid: 0, gid: 2345},
		"root group": {uid: 1234, gid: 0},
	} {
		name := name
		identity := identity
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := newClientAssetTestState(t)
			writeClientAssetTestFile(t, state.layout.manifestPath, validClientManifestV3(t))
			state.dependencies.resolveServiceIdentity = func(string, string) (clientServiceIdentity, error) {
				return identity, nil
			}
			if _, err := loadProductionClientManifestWithDependencies(
				state.layout.manifestPath,
				state.dependencies,
			); err == nil {
				t.Fatal("production loader accepted a root service identity component")
			}
		})
	}
}

func TestValidateClientServiceIdentityDataAcceptsDedicatedAccount(t *testing.T) {
	t.Parallel()

	identity, err := validateClientServiceIdentityData(
		"warptweet-client",
		"warptweet-client",
		validClientPasswdData(),
		validClientGroupData(),
	)
	if err != nil {
		t.Fatalf("validateClientServiceIdentityData: %v", err)
	}
	if identity.uid != 920 || identity.gid != 920 {
		t.Fatalf("identity = %+v, want UID:GID 920:920", identity)
	}
}

func TestValidateClientServiceIdentityDataRejectsSharedAuthority(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		passwd string
		group  string
	}{
		"duplicate service account": {
			passwd: string(validClientPasswdData()) +
				"warptweet-client:x:921:921::/nonexistent:/usr/sbin/nologin\n",
			group: string(validClientGroupData()),
		},
		"shared UID": {
			passwd: string(validClientPasswdData()) +
				"alternate:x:920:921::/nonexistent:/usr/sbin/nologin\n",
			group: string(validClientGroupData()) + "alternate:x:921:\n",
		},
		"shared primary GID": {
			passwd: string(validClientPasswdData()) +
				"alternate:x:921:920::/nonexistent:/usr/sbin/nologin\n",
			group: string(validClientGroupData()),
		},
		"duplicate service group": {
			passwd: string(validClientPasswdData()),
			group: string(validClientGroupData()) +
				"warptweet-client:x:921:\n",
		},
		"shared group GID": {
			passwd: string(validClientPasswdData()),
			group:  string(validClientGroupData()) + "alternate:x:920:\n",
		},
		"foreign primary-group member": {
			passwd: string(validClientPasswdData()),
			group:  "root:x:0:\nwarptweet-client:x:920:alternate\n",
		},
		"service user supplementary membership": {
			passwd: string(validClientPasswdData()),
			group: string(validClientGroupData()) +
				"alternate:x:921:warptweet-client\n",
		},
	}
	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := validateClientServiceIdentityData(
				"warptweet-client",
				"warptweet-client",
				[]byte(test.passwd),
				[]byte(test.group),
			); err == nil {
				t.Fatal("validation accepted shared client service authority")
			}
		})
	}
}

func TestValidateClientServiceIdentityDataRejectsUnsafeAccountShape(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		passwd string
		group  string
	}{
		"root UID": {
			passwd: "root:x:0:0:root:/root:/bin/sh\n" +
				"warptweet-client:x:0:920::/nonexistent:/usr/sbin/nologin\n",
			group: string(validClientGroupData()),
		},
		"mismatched primary group": {
			passwd: string(validClientPasswdData()),
			group:  "root:x:0:\nwarptweet-client:x:921:\n",
		},
		"password in passwd": {
			passwd: "root:x:0:0:root:/root:/bin/sh\n" +
				"warptweet-client:hash:920:920::/nonexistent:/usr/sbin/nologin\n",
			group: string(validClientGroupData()),
		},
		"interactive shell": {
			passwd: "root:x:0:0:root:/root:/bin/sh\n" +
				"warptweet-client:x:920:920::/nonexistent:/bin/sh\n",
			group: string(validClientGroupData()),
		},
	}
	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := validateClientServiceIdentityData(
				"warptweet-client",
				"warptweet-client",
				[]byte(test.passwd),
				[]byte(test.group),
			); err == nil {
				t.Fatal("validation accepted unsafe client service account shape")
			}
		})
	}
}

func TestRelativeClientStatePathRejectsEscapesAndNonCanonicalPaths(t *testing.T) {
	t.Parallel()

	root := filepath.Join(string(os.PathSeparator), "fixed", "root")
	for _, path := range []string{
		root,
		filepath.Dir(root),
		filepath.Join(root, "..", "outside"),
		filepath.Join(root, "state") + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "state",
		"relative/client.wt",
	} {
		if _, _, err := relativeClientStatePath(root, path); err == nil {
			t.Errorf("relativeClientStatePath accepted %q", path)
		}
	}
	_, relative, err := relativeClientStatePath(root, filepath.Join(root, "state", "client.wt"))
	if err != nil {
		t.Fatalf("relativeClientStatePath: %v", err)
	}
	if relative != filepath.Join("state", "client.wt") {
		t.Fatalf("relative path = %q", relative)
	}
}

func validClientManifestV3(t *testing.T) []byte {
	t.Helper()
	contents, err := json.Marshal(config.Config{
		Kind:            config.ClientTunnelsKind,
		SchemaVersion:   config.CurrentSchemaVersion,
		ProfileID:       profile.CurrentID,
		SSHBinarySHA256: strings.Repeat("a", 64),
		Server: config.Server{
			Address: netip.MustParseAddr("192.0.2.10"),
			Port:    22,
			User:    "warptweet",
		},
		Tunnels: []config.Tunnel{{
			ID: "database-primary",
			Listen: config.Endpoint{
				Address: netip.MustParseAddr("127.0.0.1"),
				Port:    15432,
			},
			Target: config.Endpoint{
				Address: netip.MustParseAddr("10.0.0.20"),
				Port:    5432,
			},
		}},
		Supervision: config.Supervision{
			InitialBackoff: config.Duration(time.Second),
			MaxBackoff:     config.Duration(30 * time.Second),
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return contents
}

func validClientPasswdData() []byte {
	return []byte(
		"root:x:0:0:root:/root:/bin/sh\n" +
			"warptweet-client:x:920:920::/nonexistent:/usr/sbin/nologin\n",
	)
}

func validClientGroupData() []byte {
	return []byte("root:x:0:\nwarptweet-client:x:920:\n")
}
