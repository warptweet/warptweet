package command

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestRenderAuthorizedKeyCommandWritesDeterministicManagedLine(t *testing.T) {
	t.Parallel()

	manifestPath, publicKeyPath, blob := writeAuthorizedKeyCommandInputs(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"render-authorized-key",
		"--config", manifestPath,
		"--public-key", publicKeyPath,
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}

	want := "restrict,port-forwarding,permitopen=\"198.51.100.7:5432\" " +
		"ssh-mldsa44-ed25519@openssh.com " + blob + " warptweet-managed-client\n"
	if stdout.String() != want {
		t.Fatalf("unexpected stdout:\n--- got ---\n%s--- want ---\n%s", stdout.String(), want)
	}
	if strings.Contains(stdout.String(), "untrusted input comment") {
		t.Fatal("command retained the input public-key comment")
	}
}

func TestRenderAuthorizedKeyCommandRejectsAmbiguousArguments(t *testing.T) {
	t.Parallel()

	manifestPath, publicKeyPath, _ := writeAuthorizedKeyCommandInputs(t)
	tests := []struct {
		name      string
		arguments []string
		wantError string
	}{
		{
			name:      "missing both flags",
			arguments: []string{"render-authorized-key"},
			wantError: "requires --config and --public-key",
		},
		{
			name: "missing public key",
			arguments: []string{
				"render-authorized-key", "--config", manifestPath,
			},
			wantError: "requires --config and --public-key",
		},
		{
			name: "missing manifest",
			arguments: []string{
				"render-authorized-key", "--public-key", publicKeyPath,
			},
			wantError: "requires --config and --public-key",
		},
		{
			name: "unexpected positional argument",
			arguments: []string{
				"render-authorized-key",
				"--config", manifestPath,
				"--public-key", publicKeyPath,
				"extra",
			},
			wantError: "unexpected positional arguments",
		},
		{
			name: "unknown flag",
			arguments: []string{
				"render-authorized-key",
				"--config", manifestPath,
				"--public-key", publicKeyPath,
				"--output", "authorized_keys",
			},
			wantError: "flag provided but not defined",
		},
		{
			name: "duplicate manifest flag",
			arguments: []string{
				"render-authorized-key",
				"--config", manifestPath,
				"--config", manifestPath,
				"--public-key", publicKeyPath,
			},
			wantError: "--config may be specified only once",
		},
		{
			name: "duplicate public-key flag",
			arguments: []string{
				"render-authorized-key",
				"--config", manifestPath,
				"--public-key", publicKeyPath,
				"--public-key", publicKeyPath,
			},
			wantError: "--public-key may be specified only once",
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

func TestRenderAuthorizedKeyCommandBoundsAndValidatesPublicKeyFile(t *testing.T) {
	t.Parallel()

	manifestPath, publicKeyPath, _ := writeAuthorizedKeyCommandInputs(t)
	directory := filepath.Dir(publicKeyPath)
	oversizedPath := filepath.Join(directory, "oversized.pub")
	if err := os.WriteFile(
		oversizedPath,
		bytes.Repeat([]byte{'a'}, server.MaxAuthorizedKeyInputBytes+1),
		0o600,
	); err != nil {
		t.Fatalf("write oversized public key: %v", err)
	}
	malformedPath := filepath.Join(directory, "malformed.pub")
	if err := os.WriteFile(malformedPath, []byte("ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatalf("write malformed public key: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{name: "oversized", path: oversizedPath, wantError: "exceeds 8192 bytes"},
		{name: "malformed", path: malformedPath, wantError: "invalid WarpTweet authorized key"},
		{name: "directory", path: directory, wantError: "must be a regular file"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{
				"render-authorized-key",
				"--config", manifestPath,
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

func TestUsageIncludesRenderAuthorizedKey(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(
		stdout.String(),
		"warptweet render-authorized-key --config <server.wt> --public-key <client.pub>",
	) {
		t.Fatalf("usage omits render-authorized-key: %s", stdout.String())
	}
}

func writeAuthorizedKeyCommandInputs(t *testing.T) (string, string, string) {
	t.Helper()

	directory := t.TempDir()
	manifest := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            strings.Repeat("a", 64),
		OpenSSHBundleManifestSHA256: strings.Repeat("b", 64),
		Listen: server.Endpoint{
			Address: netip.MustParseAddr("192.0.2.10"),
			Port:    2222,
		},
		Target: server.Endpoint{
			Address: netip.MustParseAddr("198.51.100.7"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        "/opt/warptweet/etc/ssh_host_mldsa44_ed25519_key",
		AuthorizedKeysPath: "/opt/warptweet/etc/authorized_keys/warptweet",
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal server manifest: %v", err)
	}
	manifestPath := filepath.Join(directory, "host.wt")
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatalf("write server manifest: %v", err)
	}

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	blob := commandPublicKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
	)
	publicKeyPath := filepath.Join(directory, "client.pub")
	publicKey := selectedProfile.AuthenticationKeyType + " " + blob + " untrusted input comment\n"
	if err := os.WriteFile(publicKeyPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write client public key: %v", err)
	}

	return manifestPath, publicKeyPath, blob
}

func commandPublicKeyBlob(algorithm string, rawSize int) string {
	name := []byte(algorithm)
	blob := make([]byte, 4+len(name)+4+rawSize)
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(rawSize))
	for index := 0; index < rawSize; index++ {
		blob[offset+4+index] = byte(index)
	}
	return base64.StdEncoding.EncodeToString(blob)
}
