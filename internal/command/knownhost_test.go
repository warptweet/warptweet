package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/profile"
)

func TestRenderKnownHostCommandWritesDeterministicManagedLine(t *testing.T) {
	t.Parallel()

	manifestPath, publicKeyPath, blob := writeKnownHostCommandInputs(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"render-known-host",
		"--config", manifestPath,
		"--tunnel", "database-primary",
		"--public-key", publicKeyPath,
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}

	want := "warptweet-database-primary ssh-mldsa44-ed25519@openssh.com " +
		blob + " warptweet-managed-host\n"
	if stdout.String() != want {
		t.Fatalf("unexpected stdout:\n--- got ---\n%s--- want ---\n%s", stdout.String(), want)
	}
	if strings.Contains(stdout.String(), "untrusted input comment") {
		t.Fatal("command retained the input public-key comment")
	}
}

func TestRenderKnownHostCommandRejectsAmbiguousArguments(t *testing.T) {
	t.Parallel()

	manifestPath, publicKeyPath, _ := writeKnownHostCommandInputs(t)
	tests := []struct {
		name      string
		arguments []string
		wantError string
	}{
		{
			name:      "missing all flags",
			arguments: []string{"render-known-host"},
			wantError: "requires --config, --tunnel, and --public-key",
		},
		{
			name: "missing manifest",
			arguments: []string{
				"render-known-host", "--tunnel", "database-primary", "--public-key", publicKeyPath,
			},
			wantError: "requires --config, --tunnel, and --public-key",
		},
		{
			name: "missing tunnel",
			arguments: []string{
				"render-known-host", "--config", manifestPath, "--public-key", publicKeyPath,
			},
			wantError: "requires --config, --tunnel, and --public-key",
		},
		{
			name: "missing public key",
			arguments: []string{
				"render-known-host", "--config", manifestPath, "--tunnel", "database-primary",
			},
			wantError: "requires --config, --tunnel, and --public-key",
		},
		{
			name: "unexpected positional argument",
			arguments: []string{
				"render-known-host",
				"--config", manifestPath,
				"--tunnel", "database-primary",
				"--public-key", publicKeyPath,
				"extra",
			},
			wantError: "unexpected positional arguments",
		},
		{
			name: "unknown flag",
			arguments: []string{
				"render-known-host",
				"--config", manifestPath,
				"--tunnel", "database-primary",
				"--public-key", publicKeyPath,
				"--output", "known_hosts",
			},
			wantError: "flag provided but not defined",
		},
		{
			name: "duplicate manifest flag",
			arguments: []string{
				"render-known-host",
				"--config", manifestPath,
				"--config", manifestPath,
				"--tunnel", "database-primary",
				"--public-key", publicKeyPath,
			},
			wantError: "--config may be specified only once",
		},
		{
			name: "duplicate tunnel flag",
			arguments: []string{
				"render-known-host",
				"--config", manifestPath,
				"--tunnel", "database-primary",
				"--tunnel", "database-primary",
				"--public-key", publicKeyPath,
			},
			wantError: "--tunnel may be specified only once",
		},
		{
			name: "duplicate public-key flag",
			arguments: []string{
				"render-known-host",
				"--config", manifestPath,
				"--tunnel", "database-primary",
				"--public-key", publicKeyPath,
				"--public-key", publicKeyPath,
			},
			wantError: "--public-key may be specified only once",
		},
		{
			name: "tunnel absent from manifest",
			arguments: []string{
				"render-known-host",
				"--config", manifestPath,
				"--tunnel", "missing-tunnel",
				"--public-key", publicKeyPath,
			},
			wantError: `manifest contains no tunnel with ID "missing-tunnel"`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), test.arguments, nil, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("code = %d, want 1; stderr = %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("command wrote stdout on failure: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), test.wantError)
			}
		})
	}
}

func TestRenderKnownHostCommandBoundsAndValidatesPublicKeyFile(t *testing.T) {
	t.Parallel()

	manifestPath, publicKeyPath, _ := writeKnownHostCommandInputs(t)
	directory := filepath.Dir(publicKeyPath)
	oversizedPath := filepath.Join(directory, "oversized-host.pub")
	if err := os.WriteFile(
		oversizedPath,
		bytes.Repeat([]byte{'a'}, knownhosts.MaxPublicKeyLineBytes+1),
		0o600,
	); err != nil {
		t.Fatalf("write oversized host public key: %v", err)
	}
	malformedPath := filepath.Join(directory, "malformed-host.pub")
	if err := os.WriteFile(malformedPath, []byte("ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatalf("write malformed host public key: %v", err)
	}
	symlinkPath := filepath.Join(directory, "symlink-host.pub")
	if err := os.Symlink(publicKeyPath, symlinkPath); err != nil {
		t.Fatalf("create host public-key symlink: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{name: "oversized", path: oversizedPath, wantError: "exceeds 8192 bytes"},
		{name: "malformed", path: malformedPath, wantError: "invalid WarpTweet host public key"},
		{name: "directory", path: directory, wantError: "must be a regular file"},
		{name: "symbolic link", path: symlinkPath, wantError: "must not be a symbolic link"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{
				"render-known-host",
				"--config", manifestPath,
				"--tunnel", "database-primary",
				"--public-key", test.path,
			}, nil, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("code = %d, want 1; stderr = %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("command wrote stdout on failure: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), test.wantError)
			}
		})
	}
}

func TestUsageIncludesRenderKnownHost(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(
		stdout.String(),
		"warptweet render-known-host --config <client.wt> --tunnel <id> --public-key <host.pub>",
	) {
		t.Fatalf("usage omits render-known-host: %s", stdout.String())
	}
}

func writeKnownHostCommandInputs(t *testing.T) (string, string, string) {
	t.Helper()

	manifestPath, _ := writeClientManifest(t, false)
	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	blob := commandPublicKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
	)
	publicKeyPath := filepath.Join(filepath.Dir(manifestPath), "host.pub")
	publicKey := selectedProfile.AuthenticationKeyType + " " + blob + " untrusted input comment\n"
	if err := os.WriteFile(publicKeyPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write host public key: %v", err)
	}
	return manifestPath, publicKeyPath, blob
}
