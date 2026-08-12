package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAttestClientLaunchReturnsExactValidatedCommand(t *testing.T) {
	t.Parallel()

	assets := newClientAssetTestState(t)
	spec := assets.spec
	binary := writeAttestationEngine(t, spec, false)
	launch, err := attestClientLaunchWithDependencies(
		context.Background(),
		binary,
		spec,
		testClientLaunchDependencies(assets.dependencies),
	)
	if err != nil {
		t.Fatalf("AttestClientLaunch: %v", err)
	}
	wantArguments, err := Arguments(spec)
	if err != nil {
		t.Fatalf("Arguments: %v", err)
	}
	if strings.Join(launch.Args, "\x00") != strings.Join(wantArguments, "\x00") {
		t.Fatalf("launch arguments = %q, want %q", launch.Args, wantArguments)
	}
	if launch.Path != binary.Path || launch.Preflight.SHA256 != binary.SHA256 {
		t.Fatalf("unexpected launch engine evidence: %#v", launch)
	}
	wantEnvironment := []string{"LANG=C", "LC_ALL=C"}
	if !slices.Equal(launch.Env, wantEnvironment) {
		t.Fatalf("launch environment = %q, want %q", launch.Env, wantEnvironment)
	}
	if launch.Assets.HostKeyPins != 1 {
		t.Fatalf("host-key pins = %d, want 1", launch.Assets.HostKeyPins)
	}

	calls, err := os.ReadFile(binary.Path + ".calls")
	if err != nil {
		t.Fatalf("read engine calls: %v", err)
	}
	if got := strings.Count(string(calls), "-V\n"); got != 2 {
		t.Fatalf("version preflight calls = %d, want 2; calls:\n%s", got, calls)
	}
	if got := strings.Count(string(calls), "-G "); got != 1 {
		t.Fatalf("effective-config calls = %d, want 1; calls:\n%s", got, calls)
	}
}

func TestAttestClientLaunchRejectsBinaryChangedByEffectiveCheck(t *testing.T) {
	t.Parallel()

	assets := newClientAssetTestState(t)
	spec := assets.spec
	binary := writeAttestationEngine(t, spec, true)
	_, err := attestClientLaunchWithDependencies(
		context.Background(),
		binary,
		spec,
		testClientLaunchDependencies(assets.dependencies),
	)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("AttestClientLaunch error = %v, want final hash rejection", err)
	}
}

func TestAttestClientLaunchRevalidatesAssetsOnEveryCall(t *testing.T) {
	t.Parallel()

	assets := newClientAssetTestState(t)
	spec := assets.spec
	binary := writeAttestationEngine(t, spec, false)
	dependencies := testClientLaunchDependencies(assets.dependencies)
	if _, err := attestClientLaunchWithDependencies(
		context.Background(), binary, spec, dependencies,
	); err != nil {
		t.Fatalf("first AttestClientLaunch: %v", err)
	}
	writeClientAssetTestFile(t, spec.GlobalKnownHostsFile, []byte("unexpected trust\n"))
	if _, err := attestClientLaunchWithDependencies(
		context.Background(), binary, spec, dependencies,
	); err == nil {
		t.Fatal("second AttestClientLaunch accepted changed trust assets")
	}
}

func TestAttestManagedClientLaunchReturnsReadinessBoundCommand(t *testing.T) {
	t.Parallel()

	assets := newClientAssetTestState(t)
	spec := assets.spec
	runtimeRoot := newShortPrivateRuntimeDirectory(t)
	runtimeDirectory := filepath.Join(runtimeRoot, spec.TunnelID)
	if err := os.Mkdir(runtimeDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir runtime directory: %v", err)
	}
	if err := os.Chmod(runtimeDirectory, 0o700); err != nil {
		t.Fatalf("Chmod runtime directory: %v", err)
	}
	controlPath := filepath.Join(runtimeDirectory, controlSocketName)
	binary := writeAttestationEngineWithEffective(
		t,
		spec,
		managedEffectiveOutput(spec, controlPath),
		false,
	)
	dependencies := productionManagedClientLaunchDependencies()
	dependencies.launch = testClientLaunchDependencies(assets.dependencies)
	dependencies.runtimeRoot = runtimeRoot
	dependencies.runner = &scriptedReadinessRunner{}
	dependencies.poll = time.Millisecond
	dependencies.leafOwner = fileInfoOwnedByEffectiveUser
	dependencies.ancestorOwner = acceptTestAncestorOwner

	launch, err := attestManagedClientLaunchWithDependencies(
		context.Background(),
		binary,
		runtimeDirectory,
		spec,
		dependencies,
	)
	if err != nil {
		t.Fatalf("attestManagedClientLaunchWithDependencies: %v", err)
	}
	if launch.Readiness == nil {
		t.Fatal("managed launch has no readiness gate")
	}
	policy, err := managedClientPolicyAtRoot(runtimeDirectory, spec, runtimeRoot)
	if err != nil {
		t.Fatalf("managedClientPolicyAtRoot: %v", err)
	}
	if want := clientPolicyArguments(policy); !slices.Equal(launch.Args, want) {
		t.Fatalf("managed launch arguments = %q, want %q", launch.Args, want)
	}
	if !strings.Contains(strings.Join(launch.Args, "\x00"), `ControlPath=`+controlPath) {
		t.Fatalf("managed launch does not use prepared control path: %q", launch.Args)
	}
	if err := launch.Readiness.Close(); err != nil {
		t.Fatalf("close readiness: %v", err)
	}
}

func writeAttestationEngine(t *testing.T, spec ClientSpec, mutateAfterEffective bool) Binary {
	t.Helper()
	return writeAttestationEngineWithEffective(t, spec, effectiveOutput(spec), mutateAfterEffective)
}

func writeAttestationEngineWithEffective(
	t *testing.T,
	spec ClientSpec,
	effective string,
	mutateAfterEffective bool,
) Binary {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ssh")
	mutation := ""
	if mutateAfterEffective {
		mutation = "printf '\\n# changed during effective validation\\n' >> \"$0\"\n"
	}
	script := `#!/bin/sh
[ -z "${LD_PRELOAD:-}" ] || exit 91
[ -z "${OPENSSL_CONF:-}" ] || exit 92
printf '%s\n' "$*" >> "$0.calls"
case "$1:$2" in
  -V:) echo 'OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026' >&2 ;;
  -Q:kex) echo 'mlkem768x25519-sha256' ;;
  -Q:key) echo 'ssh-mldsa44-ed25519@openssh.com' ;;
  -Q:sig) echo 'ssh-mldsa44-ed25519@openssh.com' ;;
  -Q:cipher) printf '%s\n' 'chacha20-poly1305@openssh.com' 'aes256-gcm@openssh.com' ;;
	-G:-F) cat <<'OUTPUT'
` + effective + `OUTPUT
` + mutation + `  ;;
  *) exit 64 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write attestation engine: %v", err)
	}
	digest := sha256.Sum256([]byte(script))
	return Binary{Path: path, SHA256: hex.EncodeToString(digest[:])}
}

func testClientLaunchDependencies(assetDependencies clientAssetDependencies) clientLaunchDependencies {
	dependencies := productionClientLaunchDependencies()
	dependencies.preflight.requireFixedLayout = false
	dependencies.preflight.inspector = fixedExecutableInspector{report: executableLinkageReport{
		format:           "ELF",
		openSSLLinkage:   "static",
		dynamicLibraries: []string{"libc.so.6"},
	}}
	dependencies.preflight.environment = func() []string {
		return append(os.Environ(),
			"LD_PRELOAD=/tmp/unsafe.so",
			"OPENSSL_CONF=/tmp/unsafe.cnf",
			"GLIBC_TUNABLES=glibc.malloc.check=3",
			"LOCPATH=/tmp/locale",
			"MALLOC_CHECK_=3",
		)
	}
	dependencies.validateAssets = func(spec ClientSpec) (AssetReport, error) {
		return validateAssetsWithDependencies(spec, assetDependencies)
	}
	return dependencies
}
