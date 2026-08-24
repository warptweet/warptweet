package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/strictjson"
)

func TestLoadAcceptsValidStrictConfiguration(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "client.wt")
	contents := validManifestJSON(t)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", got.SchemaVersion, CurrentSchemaVersion)
	}
	if got.Kind != ClientTunnelsKind {
		t.Fatalf("Kind = %q, want %q", got.Kind, ClientTunnelsKind)
	}
	if got.ProfileID != profile.CurrentID {
		t.Fatalf("ProfileID = %q, want %q", got.ProfileID, profile.CurrentID)
	}
	if got.Server.Host != "192.0.2.10" {
		t.Fatalf("Server.Host = %v", got.Server.Host)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].ID != "database-primary" {
		t.Fatalf("Tunnels = %#v", got.Tunnels)
	}
	if got.Supervision.InitialBackoff.Value() != time.Second {
		t.Fatalf("InitialBackoff = %s", got.Supervision.InitialBackoff.Value())
	}
}

func TestLoadRequiresWTManifestExtension(t *testing.T) {
	t.Parallel()

	tests := []string{
		"client",
		"client.json",
		"client.WT",
		"client.wt.json",
	}
	for _, name := range tests {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, validManifestJSON(t), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load accepted a manifest without the exact .wt extension")
			} else if !strings.Contains(err.Error(), ManifestExtension) {
				t.Fatalf("Load error = %q, want .wt extension error", err)
			}
		})
	}
}

func TestDecodeRejectsUnknownFieldsAtEveryObjectLevel(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"top level":   `"unexpected":true`,
		"server":      `"server_note":"no"`,
		"tunnel":      `"protocol":"tcp"`,
		"listen":      `"hostname":"localhost"`,
		"target":      `"hostname":"database"`,
		"supervision": `"jitter":true`,
	}

	for name, unknownField := range tests {
		name := name
		unknownField := unknownField
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			contents := validManifestWithUnknownField(t, name, unknownField)
			if _, err := Decode(bytes.NewReader(contents)); err == nil {
				t.Fatal("Decode accepted an unknown field")
			} else if !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Decode error = %q, want unknown-field error", err)
			}
		})
	}
}

func TestDecodeRejectsDuplicateObjectMemberNamesBeforeTypedDecoding(t *testing.T) {
	t.Parallel()

	valid := string(validManifestJSON(t))
	kindField := `"kind":"` + ClientTunnelsKind + `"`
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
				kindField+`,"\u006bind":"`+ClientTunnelsKind+`"`,
				1,
			),
			duplicateName: "kind",
		},
		{
			name:          "nested server port",
			manifest:      strings.Replace(valid, `"server":{`, `"server":{"port":2222,`, 1),
			duplicateName: "port",
		},
		{
			name:          "nested tunnel target address",
			manifest:      strings.Replace(valid, `"target":{`, `"target":{"address":"10.0.0.99",`, 1),
			duplicateName: "address",
		},
		{
			name: "duplicate unknown name takes precedence",
			manifest: strings.TrimSuffix(valid, "}") +
				`,"future":1,"f\u0075ture":2}`,
			duplicateName: "future",
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

func TestDecodeRejectsCaseInsensitiveFieldAliases(t *testing.T) {
	t.Parallel()

	valid := string(validManifestJSON(t))
	for _, manifest := range []string{
		strings.Replace(valid, `"kind":`, `"Kind":`, 1),
		strings.Replace(valid, `"address":`, `"Address":`, 1),
		strings.Replace(valid, `"kind":`, `"kind":"warptweet.server-gateway","Kind":`, 1),
	} {
		_, err := Decode(strings.NewReader(manifest))
		if err == nil {
			t.Fatal("Decode accepted a case-insensitive field alias")
		}
		var nameError *strictjson.NonCanonicalNameError
		if !errors.As(err, &nameError) {
			t.Fatalf("error type = %T, want *strictjson.NonCanonicalNameError: %v", err, err)
		}
	}
}

func TestDecodeRejectsNonNumericAddressesAndInvalidPorts(t *testing.T) {
	t.Parallel()

	tests := map[string]func(map[string]any){
		"server hostname": func(document map[string]any) {
			server := document["server"].(map[string]any)
			server["address"] = "ssh.example.test"
		},
		"target hostname": func(document map[string]any) {
			tunnel := document["tunnels"].([]any)[0].(map[string]any)
			target := tunnel["target"].(map[string]any)
			target["address"] = "database.internal"
		},
		"server port too large": func(document map[string]any) {
			server := document["server"].(map[string]any)
			server["port"] = 65536
		},
		"target fractional port": func(document map[string]any) {
			tunnel := document["tunnels"].([]any)[0].(map[string]any)
			target := tunnel["target"].(map[string]any)
			target["port"] = 443.5
		},
	}

	for name, mutate := range tests {
		name := name
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := validManifestDocument(t)
			mutate(document)
			contents, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if _, err := Decode(bytes.NewReader(contents)); err == nil {
				t.Fatal("Decode accepted invalid endpoint data")
			}
		})
	}
}

func TestDecodeRejectsMalformedDocumentBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("trailing JSON value", func(t *testing.T) {
		t.Parallel()
		contents := append(validManifestJSON(t), []byte(` {"schema_version":1}`)...)
		if _, err := Decode(bytes.NewReader(contents)); err == nil {
			t.Fatal("Decode accepted a trailing JSON value")
		}
	})

	t.Run("trailing malformed data", func(t *testing.T) {
		t.Parallel()
		contents := append(validManifestJSON(t), []byte(` !`)...)
		if _, err := Decode(bytes.NewReader(contents)); err == nil {
			t.Fatal("Decode accepted malformed trailing data")
		} else if !strings.Contains(err.Error(), "trailing data") {
			t.Fatalf("Decode error = %q, want trailing-data error", err)
		}
	})

	t.Run("invalid UTF-8", func(t *testing.T) {
		t.Parallel()
		contents := append(validManifestJSON(t), 0xff)
		if _, err := Decode(bytes.NewReader(contents)); err == nil {
			t.Fatal("Decode accepted invalid UTF-8")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		t.Parallel()
		contents := bytes.Repeat([]byte{' '}, MaxConfigBytes+1)
		if _, err := Decode(bytes.NewReader(contents)); err == nil {
			t.Fatal("Decode accepted an oversized configuration")
		}
	})

	t.Run("nil reader", func(t *testing.T) {
		t.Parallel()
		if _, err := Decode(nil); err == nil {
			t.Fatal("Decode accepted a nil reader")
		}
	})
}

func TestDecodeRequiresStringDurations(t *testing.T) {
	t.Parallel()

	document := validManifestDocument(t)
	supervision := document["supervision"].(map[string]any)
	supervision["initial_backoff"] = 1_000_000_000
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Decode(bytes.NewReader(contents)); err == nil {
		t.Fatal("Decode accepted a numeric duration")
	}
}

func TestDecodeRejectsUnsupportedSchemaAndPathFields(t *testing.T) {
	t.Parallel()

	t.Run("schema version", func(t *testing.T) {
		t.Parallel()
		document := validManifestDocument(t)
		document["schema_version"] = 1
		contents, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		_, err = Decode(bytes.NewReader(contents))
		assertValidationField(t, err, "schema_version")
	})

	for _, field := range []string{
		"ssh_binary_path",
		"private_key_path",
		"known_hosts_path",
		"global_known_hosts_path",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			document := validManifestDocument(t)
			document[field] = "/caller/selected/path"
			contents, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if _, err := Decode(bytes.NewReader(contents)); err == nil {
				t.Fatalf("Decode accepted forbidden path field %q", field)
			} else if !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Decode error = %q, want unknown-field error", err)
			}
		})
	}
}

func TestDecodeRequiresClientTunnelsKind(t *testing.T) {
	t.Parallel()

	document := validManifestDocument(t)
	delete(document, "kind")
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = Decode(bytes.NewReader(contents))
	assertValidationField(t, err, "kind")
}

func TestValidateAcceptsBoundaryValuesAndIPv6Endpoints(t *testing.T) {
	t.Parallel()

	value := validConfig()
	value.Server.Host = "2001:db8::10"
	value.Tunnels[0].Target.Address = netip.MustParseAddr("2001:db8::20")
	value.Server.Port = 1
	value.Tunnels[0].Listen.Port = 65535
	value.Tunnels[0].Target.Port = 1
	value.Supervision.InitialBackoff = Duration(MinSupervisionBackoff)
	value.Supervision.MaxBackoff = Duration(MaxSupervisionBackoff)

	if err := Validate(value); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("Config.Validate: %v", err)
	}
}

func TestValidateTunnelIDUsesManifestContract(t *testing.T) {
	t.Parallel()

	if err := ValidateTunnelID("database-primary"); err != nil {
		t.Fatalf("ValidateTunnelID: %v", err)
	}
	if err := ValidateTunnelID("database_primary"); err != nil {
		t.Fatalf("ValidateTunnelID with underscore: %v", err)
	}
	if err := ValidateTunnelID("1database"); err == nil {
		t.Fatal("ValidateTunnelID accepted an identifier that does not start with a letter")
	}

	err := ValidateTunnelID("Database/primary")
	assertValidationField(t, err, "tunnel_id")
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		field  string
		mutate func(*Config)
	}{
		{
			name:  "manifest kind",
			field: "kind",
			mutate: func(value *Config) {
				value.Kind = "warptweet.server"
			},
		},
		{
			name:  "schema version",
			field: "schema_version",
			mutate: func(value *Config) {
				value.SchemaVersion = 1
			},
		},
		{
			name:  "profile ID",
			field: "profile_id",
			mutate: func(value *Config) {
				value.ProfileID = "pq-preferred"
			},
		},
		{
			name:  "short SSH digest",
			field: "ssh_binary_sha256",
			mutate: func(value *Config) {
				value.SSHBinarySHA256 = strings.Repeat("a", 63)
			},
		},
		{
			name:  "uppercase SSH digest",
			field: "ssh_binary_sha256",
			mutate: func(value *Config) {
				value.SSHBinarySHA256 = strings.Repeat("A", 64)
			},
		},
		{
			name:  "nonhex SSH digest",
			field: "ssh_binary_sha256",
			mutate: func(value *Config) {
				value.SSHBinarySHA256 = strings.Repeat("g", 64)
			},
		},
		{
			name:  "invalid server host",
			field: "server.host",
			mutate: func(value *Config) {
				value.Server.Host = ""
			},
		},
		{
			name:  "unspecified server host",
			field: "server.host",
			mutate: func(value *Config) {
				value.Server.Host = "0.0.0.0"
			},
		},
		{
			name:  "multicast server host",
			field: "server.host",
			mutate: func(value *Config) {
				value.Server.Host = "224.0.0.1"
			},
		},
		{
			name:  "uppercase DNS server host",
			field: "server.host",
			mutate: func(value *Config) {
				value.Server.Host = "TUNNEL.EXAMPLE.COM"
			},
		},
		{
			name:  "zero server port",
			field: "server.port",
			mutate: func(value *Config) {
				value.Server.Port = 0
			},
		},
		{
			name:  "unsafe Unix user",
			field: "server.user",
			mutate: func(value *Config) {
				value.Server.User = "tunnel;admin"
			},
		},
		{
			name:  "Unix user control character",
			field: "server.user",
			mutate: func(value *Config) {
				value.Server.User = "tunnel\nadmin"
			},
		},
		{
			name:  "Unix user too long",
			field: "server.user",
			mutate: func(value *Config) {
				value.Server.User = strings.Repeat("a", maxUnixUserBytes+1)
			},
		},
		{
			name:  "no tunnels",
			field: "tunnels",
			mutate: func(value *Config) {
				value.Tunnels = nil
			},
		},
		{
			name:  "unsafe tunnel ID",
			field: "tunnels[0].id",
			mutate: func(value *Config) {
				value.Tunnels[0].ID = "../../database"
			},
		},
		{
			name:  "tunnel ID control character",
			field: "tunnels[0].id",
			mutate: func(value *Config) {
				value.Tunnels[0].ID = "database\nprimary"
			},
		},
		{
			name:  "tunnel ID too long",
			field: "tunnels[0].id",
			mutate: func(value *Config) {
				value.Tunnels[0].ID = strings.Repeat("a", maxTunnelIDBytes+1)
			},
		},
		{
			name:  "non-loopback listener",
			field: "tunnels[0].listen.address",
			mutate: func(value *Config) {
				value.Tunnels[0].Listen.Address = netip.MustParseAddr("127.0.0.2")
			},
		},
		{
			name:  "IPv6 loopback listener",
			field: "tunnels[0].listen.address",
			mutate: func(value *Config) {
				value.Tunnels[0].Listen.Address = netip.IPv6Loopback()
			},
		},
		{
			name:  "zero listener port",
			field: "tunnels[0].listen.port",
			mutate: func(value *Config) {
				value.Tunnels[0].Listen.Port = 0
			},
		},
		{
			name:  "invalid target address",
			field: "tunnels[0].target.address",
			mutate: func(value *Config) {
				value.Tunnels[0].Target.Address = netip.Addr{}
			},
		},
		{
			name:  "broadcast target address",
			field: "tunnels[0].target.address",
			mutate: func(value *Config) {
				value.Tunnels[0].Target.Address = netip.MustParseAddr("255.255.255.255")
			},
		},
		{
			name:  "zero target port",
			field: "tunnels[0].target.port",
			mutate: func(value *Config) {
				value.Tunnels[0].Target.Port = 0
			},
		},
		{
			name:  "duplicate tunnel ID",
			field: "tunnels[1].id",
			mutate: func(value *Config) {
				duplicate := value.Tunnels[0]
				duplicate.Listen.Port++
				value.Tunnels = append(value.Tunnels, duplicate)
			},
		},
		{
			name:  "duplicate listener endpoint",
			field: "tunnels[1].listen.port",
			mutate: func(value *Config) {
				duplicate := value.Tunnels[0]
				duplicate.ID = "database-secondary"
				value.Tunnels = append(value.Tunnels, duplicate)
			},
		},
		{
			name:  "initial backoff too small",
			field: "supervision.initial_backoff",
			mutate: func(value *Config) {
				value.Supervision.InitialBackoff = Duration(MinSupervisionBackoff - time.Nanosecond)
			},
		},
		{
			name:  "initial backoff too large",
			field: "supervision.initial_backoff",
			mutate: func(value *Config) {
				value.Supervision.InitialBackoff = Duration(MaxSupervisionBackoff + time.Nanosecond)
			},
		},
		{
			name:  "maximum backoff too large",
			field: "supervision.max_backoff",
			mutate: func(value *Config) {
				value.Supervision.MaxBackoff = Duration(MaxSupervisionBackoff + time.Nanosecond)
			},
		},
		{
			name:  "maximum before initial",
			field: "supervision.max_backoff",
			mutate: func(value *Config) {
				value.Supervision.InitialBackoff = Duration(2 * time.Second)
				value.Supervision.MaxBackoff = Duration(time.Second)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validConfig()
			test.mutate(&value)
			err := Validate(value)
			if err == nil {
				t.Fatal("Validate accepted invalid configuration")
			}
			var validationError *ValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("Validate error type = %T, want *ValidationError", err)
			}
			if validationError.Field != test.field {
				t.Fatalf("ValidationError.Field = %q, want %q (error: %v)", validationError.Field, test.field, err)
			}
		})
	}
}

func TestDecodeCanonicalizesDNSServerHostCasing(t *testing.T) {
	t.Parallel()

	value := validConfig()
	value.Server.Host = "TUNNEL.EXAMPLE.COM"
	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Server.Host != "tunnel.example.com" {
		t.Fatalf("host=%q", decoded.Server.Host)
	}
}

func TestDurationJSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := Duration(1500 * time.Millisecond)
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(encoded) != `"1.5s"` {
		t.Fatalf("Marshal = %s, want %q", encoded, `"1.5s"`)
	}

	var decoded Duration
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded != original {
		t.Fatalf("decoded = %s, want %s", decoded.Value(), original.Value())
	}
}

func validConfig() Config {
	return Config{
		Kind:            ClientTunnelsKind,
		SchemaVersion:   CurrentSchemaVersion,
		ProfileID:       profile.CurrentID,
		SSHBinarySHA256: strings.Repeat("a", 64),
		Server: Server{
			Host: "192.0.2.10",
			Port: 22,
			User: "warptweet",
		},
		Tunnels: []Tunnel{
			{
				ID: "database-primary",
				Listen: Endpoint{
					Address: netip.MustParseAddr("127.0.0.1"),
					Port:    15432,
				},
				Target: Endpoint{
					Address: netip.MustParseAddr("10.0.0.20"),
					Port:    5432,
				},
			},
		},
		Supervision: Supervision{
			InitialBackoff: Duration(time.Second),
			MaxBackoff:     Duration(30 * time.Second),
		},
	}
}

func assertValidationField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("operation accepted invalid %s", field)
	}
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error type = %T, want *ValidationError", err)
	}
	if validationError.Field != field {
		t.Fatalf("ValidationError.Field = %q, want %q (error: %v)", validationError.Field, field, err)
	}
}

func validManifestJSON(t *testing.T) []byte {
	t.Helper()
	contents, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatalf("Marshal valid config: %v", err)
	}
	return contents
}

func validManifestDocument(t *testing.T) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(validManifestJSON(t), &document); err != nil {
		t.Fatalf("Unmarshal valid document: %v", err)
	}
	return document
}

func validManifestWithUnknownField(t *testing.T, level, unknownField string) []byte {
	t.Helper()
	document := validManifestDocument(t)
	var target map[string]any
	switch level {
	case "top level":
		target = document
	case "server":
		target = document["server"].(map[string]any)
	case "tunnel":
		target = document["tunnels"].([]any)[0].(map[string]any)
	case "listen":
		tunnel := document["tunnels"].([]any)[0].(map[string]any)
		target = tunnel["listen"].(map[string]any)
	case "target":
		tunnel := document["tunnels"].([]any)[0].(map[string]any)
		target = tunnel["target"].(map[string]any)
	case "supervision":
		target = document["supervision"].(map[string]any)
	default:
		t.Fatalf("unknown test level %q", level)
	}

	var field map[string]any
	if err := json.Unmarshal([]byte("{"+unknownField+"}"), &field); err != nil {
		t.Fatalf("Unmarshal unknown field: %v", err)
	}
	for name, value := range field {
		target[name] = value
	}

	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal document: %v", err)
	}
	return contents
}
