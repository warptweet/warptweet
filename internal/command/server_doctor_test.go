package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/engine"
	"warptweet.com/warptweet/internal/profile"
)

func TestDoctorServerRejectsAmbiguousArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		arguments []string
		wantError string
	}{
		{name: "missing config", arguments: []string{"doctor-server"}, wantError: "requires --config"},
		{name: "unknown flag", arguments: []string{"doctor-server", "--unknown"}, wantError: "flag provided but not defined"},
		{
			name: "duplicate config",
			arguments: []string{
				"doctor-server", "--config", "one.wt", "--config", "two.wt",
			},
			wantError: "--config may be specified only once",
		},
		{
			name:      "positional argument",
			arguments: []string{"doctor-server", "--config", "server.wt", "extra"},
			wantError: "unexpected positional arguments",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), test.arguments, nil, &stdout, &stderr)
			if code == 0 {
				t.Fatal("doctor-server accepted invalid arguments")
			}
			if stdout.Len() != 0 {
				t.Fatalf("doctor-server wrote stdout on failure: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), test.wantError)
			}
		})
	}
}

func TestDoctorServerDispatchesToInstalledPreflight(t *testing.T) {
	manifestPath, _, _ := writeAuthorizedKeyCommandInputs(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{"doctor-server", "--config", manifestPath},
		nil,
		&stdout,
		&stderr,
	)
	if code == 0 {
		t.Fatal("doctor-server unexpectedly accepted the synthetic uninstalled server")
	}
	if stdout.Len() != 0 {
		t.Fatalf("doctor-server wrote stdout before preflight completed: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("doctor-server was not dispatched: %s", stderr.String())
	}
}

func TestServerDoctorOutputContainsOnlyNonSecretAttestationFacts(t *testing.T) {
	t.Parallel()

	output := newServerDoctorOutput(engine.ServerPreflightReport{
		SSHDPath:                    "/opt/warptweet/libexec/openssh/sbin/sshd",
		SSHDBinarySHA256:            strings.Repeat("a", 64),
		OpenSSHBundleManifestSHA256: strings.Repeat("b", 64),
		EngineVersion:               "OpenSSH_10.4p1",
		Profile:                     "profile-id",
		OpenSSLVersion:              "3.5.7",
		OpenSSLVersionText:          "OpenSSL 3.5.7 9 Jun 2026",
		OpenSSLLinkage:              "static",
		ExecutableFormat:            "ELF",
		StaticLibcryptoSHA256:       strings.Repeat("d", 64),
		HostPublicKeySHA256:         strings.Repeat("c", 64),
		AuthorizedKeyCount:          1,
	}, profile.AuthenticationBindingOpenSSHVendor, profile.SupportStatusPublishedMatrix)

	if output.Status != "preflight_ready" || output.Role != "server" ||
		output.Profile != "profile-id" ||
		output.AuthenticationBindingStatus != string(profile.AuthenticationBindingOpenSSHVendor) ||
		output.SupportStatus != string(profile.SupportStatusPublishedMatrix) ||
		output.EngineVersion != "OpenSSH_10.4p1" || output.AuthorizedKeyCount != 1 ||
		output.OpenSSLVersion != "3.5.7" ||
		output.OpenSSLVersionText != "OpenSSL 3.5.7 9 Jun 2026" ||
		output.OpenSSLLinkage != "static" || output.ExecutableFormat != "ELF" {
		t.Fatalf("unexpected server doctor output: %+v", output)
	}
	if output.SSHDBinarySHA256 != strings.Repeat("a", 64) ||
		output.OpenSSHBundleManifestSHA256 != strings.Repeat("b", 64) ||
		output.HostPublicKeySHA256 != strings.Repeat("c", 64) ||
		output.StaticLibcryptoSHA256 != strings.Repeat("d", 64) {
		t.Fatalf("server doctor output omitted attestation digests: %+v", output)
	}
	var encoded bytes.Buffer
	if err := writeJSON(&encoded, output); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	for _, evidence := range []string{
		`"openssl_version":"3.5.7"`,
		`"openssl_version_text":"OpenSSL 3.5.7 9 Jun 2026"`,
		`"openssl_linkage":"static"`,
		`"executable_format":"ELF"`,
		`"static_libcrypto_sha256":"` + strings.Repeat("d", 64) + `"`,
	} {
		if !strings.Contains(encoded.String(), evidence) {
			t.Errorf("server doctor JSON omits %s: %s", evidence, encoded.String())
		}
	}
}

func TestUsageIncludesDoctorServer(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "warptweet doctor-server --config <server.wt>") {
		t.Fatalf("usage omits doctor-server: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "warptweet run --config <client.wt> --tunnel <id> [--once]") {
		t.Fatalf("usage omits closed run command: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "--runtime-dir") {
		t.Fatalf("usage exposes removed runtime-directory option: %s", stdout.String())
	}
}
