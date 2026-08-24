package server

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/strictjson"
)

func TestDecodeAcceptsStrictServerManifest(t *testing.T) {
	t.Parallel()

	manifest := marshalManifest(t, validConfig())
	got, err := Decode(strings.NewReader(manifest))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != validConfig() {
		t.Fatalf("Decode returned %#v, want %#v", got, validConfig())
	}
}

func TestDecodeRejectsMalformedOrUnboundedInput(t *testing.T) {
	t.Parallel()

	valid := marshalManifest(t, validConfig())
	tests := []struct {
		name   string
		reader io.Reader
		want   string
	}{
		{
			name:   "nil reader",
			reader: nil,
			want:   "reader is nil",
		},
		{
			name:   "unknown field",
			reader: strings.NewReader(strings.TrimSuffix(valid, "}") + `,"fallback":true}`),
			want:   "unknown field",
		},
		{
			name:   "trailing JSON value",
			reader: strings.NewReader(valid + ` {}`),
			want:   "trailing JSON value",
		},
		{
			name:   "trailing malformed data",
			reader: strings.NewReader(valid + ` !`),
			want:   "trailing data",
		},
		{
			name:   "invalid UTF-8",
			reader: strings.NewReader(string([]byte{'{', 0xff, '}'})),
			want:   "not valid UTF-8",
		},
		{
			name:   "oversized",
			reader: strings.NewReader(strings.Repeat(" ", MaxManifestBytes+1)),
			want:   "exceeds",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := Decode(test.reader)
			if err == nil {
				t.Fatal("Decode accepted invalid input")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Decode error %q does not contain %q", err, test.want)
			}
		})
	}
}

func TestDecodeRejectsDuplicateObjectMemberNamesBeforeTypedDecoding(t *testing.T) {
	t.Parallel()

	valid := marshalManifest(t, validConfig())
	kindField := `"kind":"` + ManifestKind + `"`
	tests := []struct {
		name          string
		manifest      string
		duplicateName string
	}{
		{
			name: "top-level escaped kind",
			manifest: strings.Replace(
				valid,
				kindField,
				kindField+`,"\u006bind":"`+ManifestKind+`"`,
				1,
			),
			duplicateName: "kind",
		},
		{
			name:          "nested target port",
			manifest:      strings.Replace(valid, `"target":{`, `"target":{"port":443,`, 1),
			duplicateName: "port",
		},
		{
			name:          "nested listen address",
			manifest:      strings.Replace(valid, `"listen":{`, `"listen":{"address":"192.0.2.99",`, 1),
			duplicateName: "address",
		},
		{
			name: "duplicate unknown name takes precedence",
			manifest: strings.TrimSuffix(valid, "}") +
				`,"fallback":true,"fall\u0062ack":false}`,
			duplicateName: "fallback",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Decode(strings.NewReader(test.manifest))
			if err == nil {
				t.Fatal("Decode accepted a duplicate object member name")
			}
			var duplicateError *strictjson.DuplicateNameError
			if !errors.As(err, &duplicateError) {
				t.Fatalf("error type = %T, want wrapped *strictjson.DuplicateNameError: %v", err, err)
			}
			if duplicateError.Name != test.duplicateName {
				t.Fatalf("DuplicateNameError.Name = %q, want %q", duplicateError.Name, test.duplicateName)
			}
		})
	}
}

func TestDecodeRejectsCaseInsensitiveAliasesBeforeTypedDecoding(t *testing.T) {
	t.Parallel()

	valid := marshalManifest(t, validConfig())
	tests := []struct {
		name       string
		manifest   string
		memberName string
	}{
		{
			name:       "top-level kind alias",
			manifest:   strings.Replace(valid, `"kind":`, `"Kind":`, 1),
			memberName: "Kind",
		},
		{
			name: "top-level digest alias",
			manifest: strings.Replace(
				valid,
				`"sshd_binary_sha256":`,
				`"SSHDBinarySHA256":`,
				1,
			),
			memberName: "SSHDBinarySHA256",
		},
		{
			name:       "nested address alias",
			manifest:   strings.Replace(valid, `"address":`, `"Address":`, 1),
			memberName: "Address",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := Decode(strings.NewReader(test.manifest))
			if err == nil {
				t.Fatal("Decode accepted a case-insensitive object member alias")
			}
			var nameError *strictjson.NonCanonicalNameError
			if !errors.As(err, &nameError) {
				t.Fatalf("error type = %T, want wrapped *strictjson.NonCanonicalNameError: %v", err, err)
			}
			if nameError.Name != test.memberName {
				t.Fatalf("NonCanonicalNameError.Name = %q, want %q", nameError.Name, test.memberName)
			}
		})
	}
}

func TestDecodeRejectsSchemaVersion1Document(t *testing.T) {
	t.Parallel()

	v1 := `{
  "kind": "warptweet.server-gateway",
  "schema_version": 1,
  "profile_id": "warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20",
  "sshd_binary_sha256": "` + strings.Repeat("a", 64) + `",
  "openssh_bundle_manifest_sha256": "` + strings.Repeat("b", 64) + `",
  "listen": {"address": "192.0.2.10", "port": 2222},
  "target": {"address": "198.51.100.7", "port": 5432},
  "dedicated_user": "warptweet",
  "host_key_path": "/var/lib/warptweet/ssh/ssh_host_mldsa44_ed25519_key",
  "authorized_keys_path": "/var/lib/warptweet/authorized_keys/warptweet"
}`
	_, err := Decode(strings.NewReader(v1))
	if err == nil {
		t.Fatal("Decode accepted a schema 1 server-gateway document")
	}
	if !strings.Contains(err.Error(), "unknown field") && !strings.Contains(err.Error(), "SchemaVersion") {
		t.Fatalf("schema 1 error = %v", err)
	}
}

func TestDecodeRunsSecurityValidation(t *testing.T) {
	t.Parallel()

	config := validConfig()
	config.Target.Port = 0
	_, err := Decode(strings.NewReader(marshalManifest(t, config)))
	if err == nil {
		t.Fatal("Decode accepted an invalid forwarding target")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Decode error does not wrap ErrInvalidConfig: %v", err)
	}
}

func TestDecodeRequiresServerManifestDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
		field  string
	}{
		{
			name: "unsupported schema version",
			mutate: func(config *Config) {
				config.SchemaVersion = 1
			},
			field: "SchemaVersion",
		},
		{
			name: "missing sshd digest",
			mutate: func(config *Config) {
				config.SSHDBinarySHA256 = ""
			},
			field: "SSHDBinarySHA256",
		},
		{
			name: "missing bundle manifest digest",
			mutate: func(config *Config) {
				config.OpenSSHBundleManifestSHA256 = ""
			},
			field: "OpenSSHBundleManifestSHA256",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			config := validConfig()
			test.mutate(&config)
			_, err := Decode(strings.NewReader(marshalManifest(t, config)))
			if err == nil {
				t.Fatal("Decode accepted a server manifest missing required policy")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error does not wrap ErrInvalidConfig: %v", err)
			}
			if !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error %q does not identify field %q", err, test.field)
			}
		})
	}
}

func TestLoadRequiresWTFileAndLoadsIt(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "gateway.wt")
	if err := os.WriteFile(manifestPath, []byte(marshalManifest(t, validConfig())), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != validConfig() {
		t.Fatalf("Load returned %#v, want %#v", got, validConfig())
	}

	for _, path := range []string{
		filepath.Join(directory, "gateway.json"),
		filepath.Join(directory, "gateway.WT"),
		filepath.Join(directory, "gateway"),
	} {
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), ".wt") {
			t.Fatalf("Load(%q) did not reject the extension: %v", path, err)
		}
	}
}

func marshalManifest(t *testing.T, config Config) string {
	t.Helper()

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return string(data)
}
