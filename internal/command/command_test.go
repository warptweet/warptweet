package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/engine"
	"warptweet.com/warptweet/internal/profile"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if stdout.String() != "WarpTweet "+Version+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestProfileReportsStaticOpenSSLContract(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"profile"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	var output struct {
		ID                          string `json:"id"`
		OpenSSLVersion              string `json:"openssl_version"`
		OpenSSLVersionText          string `json:"openssl_version_text"`
		OpenSSLLinkage              string `json:"openssl_linkage"`
		ExecutableFormat            string `json:"executable_format"`
		AuthenticationBindingStatus string `json:"authentication_binding_status"`
		SupportStatus               string `json:"support_status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode profile output: %v", err)
	}
	if output.ID != profile.CurrentID || output.OpenSSLVersion != profile.OpenSSLVersion ||
		output.OpenSSLVersionText != profile.OpenSSLVersionText ||
		output.OpenSSLLinkage != profile.OpenSSLLinkage ||
		output.ExecutableFormat != profile.ExecutableFormat ||
		output.AuthenticationBindingStatus != string(profile.AuthenticationBindingOpenSSHVendor) ||
		output.SupportStatus != string(profile.SupportStatusPublishedMatrix) {
		t.Fatalf("unexpected profile output: %#v", output)
	}
}

func TestValidateClientManifest(t *testing.T) {
	t.Parallel()

	manifestPath, _ := writeClientManifest(t, false)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"validate", "--config", manifestPath}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"kind":"warptweet.client-tunnels"`) ||
		!strings.Contains(stdout.String(), `"authentication_binding_status":"openssh-vendor-qualified"`) ||
		!strings.Contains(stdout.String(), `"support_status":"published-matrix"`) {
		t.Fatalf("unexpected validation output: %s", stdout.String())
	}
}

func TestRenderClientContainsExactProfile(t *testing.T) {
	t.Parallel()

	manifestPath, _ := writeClientManifest(t, false)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"render-client", "--config", manifestPath, "--tunnel", "database-primary",
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `KexAlgorithms "mlkem768x25519-sha256"`) ||
		!strings.Contains(stdout.String(), `HostKeyAlias "warptweet-database-primary"`) {
		t.Fatalf("unexpected client configuration: %s", stdout.String())
	}
}

func TestRunOnceExercisesCompleteLocalControlPlane(t *testing.T) {
	requireWritableProductionRuntime(t)
	manifestPath, enginePath := writeClientManifest(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies(ctx, []string{
		"run",
		"--config", manifestPath,
		"--tunnel", "database-primary",
		"--once",
		"--managed-lifecycle",
	}, &stdout, &stderr, testCommandDependencies(t, enginePath, nil))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if count := strings.Count(stderr.String(), `"msg":"WarpTweet tunnel preflight passed"`); count != 1 {
		t.Fatalf("preflight event missing: %s", stderr.String())
	}
	for _, evidence := range []string{
		`"openssl_version":"3.5.7"`,
		`"openssl_linkage":"static"`,
		`"executable_format":"ELF"`,
		`"elf_needed":["libc.so.6"]`,
	} {
		if !strings.Contains(stderr.String(), evidence) {
			t.Errorf("preflight event omits %s: %s", evidence, stderr.String())
		}
	}
	for _, forbidden := range []string{
		filepath.Join(filepath.Dir(manifestPath), "identity"),
		filepath.Join(filepath.Dir(manifestPath), "known_hosts"),
		"127.0.0.1:15432:10.0.0.20:5432",
		`"-L"`,
	} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("attestation log leaked %q: %s", forbidden, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), `"msg":"WarpTweet tunnel authenticated forward ready"`) ||
		!strings.Contains(stderr.String(), `"target_health":"not_checked"`) {
		t.Fatalf("authenticated readiness event missing: %s", stderr.String())
	}
}

func TestDoctorReportsStaticOpenSSLEvidence(t *testing.T) {
	manifestPath, enginePath := writeClientManifest(t, true)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{
		"doctor", "--config", manifestPath, "--tunnel", "database-primary",
	}, &stdout, &stderr, testCommandDependencies(t, enginePath, nil))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	var output clientDoctorOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode doctor output: %v", err)
	}
	if output.Status != "preflight_ready" || output.EngineVersion != "OpenSSH_10.4p1" ||
		output.OpenSSLVersion != "3.5.7" || output.OpenSSLVersionText != "OpenSSL 3.5.7 9 Jun 2026" ||
		output.OpenSSLLinkage != "static" || output.ExecutableFormat != "ELF" ||
		len(output.ELFNeeded) != 1 || output.ELFNeeded[0] != "libc.so.6" {
		t.Fatalf("unexpected doctor evidence: %#v", output)
	}
}

func TestProductionNetworkCommandsRequireFixedClientManifest(t *testing.T) {
	t.Parallel()

	manifestPath, _ := writeClientManifest(t, false)
	for _, arguments := range [][]string{
		{"doctor", "--config", manifestPath, "--tunnel", "database-primary"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Run(context.Background(), arguments, nil, &stdout, &stderr); code != 1 {
			t.Fatalf("%v code = %d, want 1; stderr = %s", arguments, code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("%v wrote stdout before fixed-manifest validation: %q", arguments, stdout.String())
		}
		layout, err := productionClientLayout()
		if err != nil {
			t.Fatalf("productionClientLayout: %v", err)
		}
		if !strings.Contains(stderr.String(), layout.ClientManifestPath) {
			t.Fatalf("%v error omits fixed manifest path: %s", arguments, stderr.String())
		}
	}
}

func TestRunFailsClosedWhenServiceReadinessCannotBePublished(t *testing.T) {
	requireWritableProductionRuntime(t)
	manifestPath, enginePath := writeClientManifest(t, true)
	dependencies := testCommandDependencies(t, enginePath, nil)
	dependencies.newServiceNotifier = func() (serviceNotifier, error) {
		return failingReadyNotifier{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies(ctx, []string{
		"run",
		"--config", manifestPath,
		"--tunnel", "database-primary",
		"--once",
		"--managed-lifecycle",
	}, &stdout, &stderr, dependencies)
	if code != 1 {
		t.Fatalf("code = %d, want 1; stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "publish tunnel readiness") {
		t.Fatalf("readiness publication failure missing: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), `"msg":"WarpTweet tunnel authenticated forward ready"`) {
		t.Fatalf("failed readiness publication was logged as ready: %s", stderr.String())
	}
}

func TestRejectsUnknownCommand(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"not-a-command"}, nil, &bytes.Buffer{}, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func requireWritableProductionRuntime(t *testing.T) {
	t.Helper()

	layout, err := productionClientLayout()
	if err != nil {
		t.Fatalf("productionClientLayout: %v", err)
	}
	directory := filepath.Join(layout.ClientRuntimeRoot, "database-primary")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Skipf("production client runtime %q is not writable: %v", layout.ClientRuntimeRoot, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
}

func writeClientManifest(t *testing.T, capableEngine bool) (string, string) {
	t.Helper()

	directory := t.TempDir()
	enginePath := filepath.Join(directory, "ssh")
	script := "not executable"
	if capableEngine {
		script = "#!/bin/sh\nwhile :; do :; done\n"
	}
	if err := os.WriteFile(enginePath, []byte(script), 0o700); err != nil {
		t.Fatalf("write engine: %v", err)
	}
	digest := sha256.Sum256([]byte(script))

	manifest := config.Config{
		Kind:            config.ClientTunnelsKind,
		SchemaVersion:   config.CurrentSchemaVersion,
		ProfileID:       profile.CurrentID,
		SSHBinarySHA256: hex.EncodeToString(digest[:]),
		Server: config.Server{
			Host: "192.0.2.10",
			Port: 2222,
			User: "warptweet",
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
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifestPath := filepath.Join(directory, "client.wt")
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return manifestPath, enginePath
}

func testCommandDependencies(t *testing.T, enginePath string, onReady func()) commandDependencies {
	t.Helper()
	preflight := func(
		_ context.Context,
		binary engine.Binary,
		selected profile.Profile,
	) (engine.PreflightReport, error) {
		return testClientPreflightReport(binary, selected), nil
	}
	return commandDependencies{
		loadProductionClientManifest: config.Load,
		preflightClient:              preflight,
		validateClientAssets: func(spec engine.ClientSpec) (engine.AssetReport, error) {
			return engine.AssetReport{
				HostKeyAlias: "warptweet-" + spec.TunnelID,
				HostKeyPins:  1,
			}, nil
		},
		validateEffectiveClient: func(
			_ context.Context,
			_ string,
			_ engine.ClientSpec,
		) error {
			return nil
		},
		attestManagedClient: func(
			_ context.Context,
			binary engine.Binary,
			runtimeDirectory string,
			spec engine.ClientSpec,
		) (engine.ManagedClientLaunch, error) {
			layout, err := productionClientLayout()
			if err != nil {
				return engine.ManagedClientLaunch{}, err
			}
			expectedRuntime := filepath.Join(layout.ClientRuntimeRoot, spec.TunnelID)
			if runtimeDirectory != expectedRuntime {
				return engine.ManagedClientLaunch{}, fmt.Errorf(
					"runtime directory = %q, want %q",
					runtimeDirectory,
					expectedRuntime,
				)
			}
			return engine.ManagedClientLaunch{
				ClientLaunch: engine.ClientLaunch{
					Path:      enginePath,
					Args:      []string{"managed-test-child"},
					Env:       []string{"LANG=C", "LC_ALL=C"},
					Preflight: testClientPreflightReport(binary, spec.Profile),
					Assets: engine.AssetReport{
						HostKeyAlias: "warptweet-" + spec.TunnelID,
						HostKeyPins:  1,
					},
				},
				Readiness: &immediateReadiness{},
			}, nil
		},
		newServiceNotifier: func() (serviceNotifier, error) {
			return &recordingServiceNotifier{onReady: onReady}, nil
		},
		authorizeManagedRun: func() error { return nil },
	}
}

type immediateReadiness struct{}

func (*immediateReadiness) Await(context.Context, int) error { return nil }
func (*immediateReadiness) Close() error                     { return nil }

type recordingServiceNotifier struct {
	onReady func()
}

func (notifier *recordingServiceNotifier) Ready(string) error {
	if notifier.onReady != nil {
		notifier.onReady()
	}
	return nil
}
func (*recordingServiceNotifier) Stopping(string) error { return nil }

type failingReadyNotifier struct{}

func (failingReadyNotifier) Ready(string) error    { return errors.New("notification transport failed") }
func (failingReadyNotifier) Stopping(string) error { return nil }

func testClientPreflightReport(binary engine.Binary, selected profile.Profile) engine.PreflightReport {
	return engine.PreflightReport{
		Path:               binary.Path,
		SHA256:             binary.SHA256,
		Version:            selected.EngineVersion,
		Profile:            selected.ID,
		ArtifactProfileID:  "linux-amd64",
		OpenSSLVersion:     selected.OpenSSLVersion,
		OpenSSLVersionText: selected.OpenSSLVersionText,
		OpenSSLLinkage:     selected.OpenSSLLinkage,
		ExecutableFormat:   selected.ExecutableFormat,
		DynamicLibraries:   []string{"libc.so.6"},
	}
}
