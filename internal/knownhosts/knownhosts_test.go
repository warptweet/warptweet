package knownhosts

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/profile"
)

func TestRenderManagedHostProducesExactDeterministicEntry(t *testing.T) {
	t.Parallel()

	selectedProfile := currentProfile(t)
	blob := publicKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	want := "warptweet-database-primary " + selectedProfile.AuthenticationKeyType +
		" " + blob + " warptweet-managed-host\n"
	inputs := map[string][]byte{
		"no comment or LF": []byte(selectedProfile.AuthenticationKeyType + " " + blob),
		"terminal LF":      []byte(selectedProfile.AuthenticationKeyType + " " + blob + "\n"),
		"discarded comment": []byte(
			selectedProfile.AuthenticationKeyType + " " + blob + " workstation key\n",
		),
		"repeated separators": []byte(
			selectedProfile.AuthenticationKeyType + "   " + blob + "   discarded comment",
		),
	}

	for name, input := range inputs {
		name := name
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := RenderManagedHost("database-primary", input)
			if err != nil {
				t.Fatalf("RenderManagedHost: %v", err)
			}
			if string(got) != want {
				t.Fatalf("unexpected managed host entry:\n--- got ---\n%s--- want ---\n%s", got, want)
			}
			if strings.Contains(string(got), "workstation") || strings.Contains(string(got), "discarded") {
				t.Fatal("RenderManagedHost retained an input comment")
			}
		})
	}
}

func TestRenderManagedHostUsesManifestTunnelIDContract(t *testing.T) {
	t.Parallel()

	selectedProfile := currentProfile(t)
	input := []byte(selectedProfile.AuthenticationKeyType + " " + publicKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	))

	got, err := RenderManagedHost("api_v2", input)
	if err != nil {
		t.Fatalf("RenderManagedHost: %v", err)
	}
	if !bytes.HasPrefix(got, []byte("warptweet-api_v2 ")) {
		t.Fatalf("managed alias = %q, want warptweet-api_v2", bytes.Fields(got)[0])
	}

	invalidIDs := []string{
		"",
		"1database",
		"Database",
		"-database",
		"database-",
		"database.primary",
		"database/primary",
		"database primary",
		"database\nprimary",
		strings.Repeat("a", 65),
	}
	for _, tunnelID := range invalidIDs {
		tunnelID := tunnelID
		t.Run(tunnelID, func(t *testing.T) {
			t.Parallel()
			_, err := RenderManagedHost(tunnelID, input)
			if err == nil {
				t.Fatal("RenderManagedHost accepted an invalid tunnel ID")
			}
			var validationError *config.ValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("error type = %T, want wrapped *config.ValidationError: %v", err, err)
			}
			if validationError.Field != "tunnel_id" {
				t.Fatalf("ValidationError.Field = %q, want tunnel_id", validationError.Field)
			}
		})
	}
}

func TestRenderManagedHostAcceptsMaximumBoundedInput(t *testing.T) {
	t.Parallel()

	selectedProfile := currentProfile(t)
	blob := publicKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	prefix := selectedProfile.AuthenticationKeyType + " " + blob + " "
	if len(prefix) >= MaxPublicKeyLineBytes {
		t.Fatalf("test prefix is %d bytes, limit is %d", len(prefix), MaxPublicKeyLineBytes)
	}
	input := []byte(prefix + strings.Repeat("c", MaxPublicKeyLineBytes-len(prefix)))
	if len(input) != MaxPublicKeyLineBytes {
		t.Fatalf("test input is %d bytes, want %d", len(input), MaxPublicKeyLineBytes)
	}
	if _, err := RenderManagedHost("maximum-input", input); err != nil {
		t.Fatalf("RenderManagedHost at size limit: %v", err)
	}

	input = append(input, 'c')
	_, err := RenderManagedHost("maximum-input", input)
	assertInvalidHostPublicKey(t, err)
}

func TestRenderManagedHostRejectsUnsafePublicKeyLines(t *testing.T) {
	t.Parallel()

	selectedProfile := currentProfile(t)
	validBlob := publicKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	validLine := selectedProfile.AuthenticationKeyType + " " + validBlob
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: nil},
		{name: "LF only", input: []byte("\n")},
		{name: "missing blob", input: []byte(selectedProfile.AuthenticationKeyType)},
		{name: "leading space", input: []byte(" " + validLine)},
		{name: "trailing space", input: []byte(validLine + " ")},
		{name: "trailing empty comment", input: []byte(validLine + "   ")},
		{name: "second public-key line", input: []byte(validLine + "\n" + validLine)},
		{name: "trailing blank line", input: []byte(validLine + "\n\n")},
		{name: "CRLF", input: []byte(validLine + "\r\n")},
		{name: "tab separator", input: []byte(selectedProfile.AuthenticationKeyType + "\t" + validBlob)},
		{name: "NUL in comment", input: []byte(validLine + " comment\x00")},
		{name: "DEL in comment", input: []byte(validLine + " comment\x7f")},
		{name: "Unicode control in comment", input: []byte(validLine + " comment\u0085")},
		{name: "invalid UTF-8", input: append([]byte(validLine+" comment"), 0xff)},
		{name: "known-hosts host prefix", input: []byte("example.test " + validLine)},
		{name: "authorized-keys option", input: []byte("restrict " + validLine)},
		{name: "wrong outer algorithm", input: []byte("ssh-ed25519 " + validBlob)},
		{
			name:  "certificate outer algorithm",
			input: []byte("ssh-mldsa44-ed25519-cert-v01@openssh.com " + validBlob),
		},
		{name: "invalid base64", input: []byte(selectedProfile.AuthenticationKeyType + " ***")},
		{
			name: "wrong inner algorithm",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + publicKeyBlob(
				"ssh-ed25519",
				selectedProfile.RawPublicKeyBytes,
				nil,
			)),
		},
		{
			name: "short raw public key",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + publicKeyBlob(
				selectedProfile.AuthenticationKeyType,
				selectedProfile.RawPublicKeyBytes-1,
				nil,
			)),
		},
		{
			name: "long raw public key",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + publicKeyBlob(
				selectedProfile.AuthenticationKeyType,
				selectedProfile.RawPublicKeyBytes+1,
				nil,
			)),
		},
		{
			name: "trailing blob bytes",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + publicKeyBlob(
				selectedProfile.AuthenticationKeyType,
				selectedProfile.RawPublicKeyBytes,
				[]byte{1},
			)),
		},
		{
			name: "truncated SSH string",
			input: []byte(selectedProfile.AuthenticationKeyType + " " +
				base64.StdEncoding.EncodeToString([]byte{0, 0, 0})),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := RenderManagedHost("database-primary", test.input)
			assertInvalidHostPublicKey(t, err)
		})
	}
}

func currentProfile(t *testing.T) profile.Profile {
	t.Helper()
	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	return selectedProfile
}

func publicKeyBlob(algorithm string, rawSize int, trailing []byte) string {
	name := []byte(algorithm)
	blob := make([]byte, 4+len(name)+4+rawSize+len(trailing))
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(rawSize))
	for index := 0; index < rawSize; index++ {
		blob[offset+4+index] = byte(index)
	}
	copy(blob[offset+4+rawSize:], trailing)
	return base64.StdEncoding.EncodeToString(blob)
}

func assertInvalidHostPublicKey(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("RenderManagedHost accepted unsafe public-key input")
	}
	if !errors.Is(err, ErrInvalidHostPublicKey) {
		t.Fatalf("error does not wrap ErrInvalidHostPublicKey: %v", err)
	}
}
