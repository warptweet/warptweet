// Package config loads and validates WarpTweet client manifests.
//
// A .wt manifest is strict JSON whose schema_version must be 2. Duplicate or
// unknown fields and trailing JSON values are rejected so configuration
// mistakes cannot silently weaken tunnel policy. Schema 1 is rejected.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// CurrentSchemaVersion is the only configuration schema understood by this
	// package. A semantic change to the schema requires a new version. Schema 1
	// is rejected.
	CurrentSchemaVersion = 2

	// ManifestExtension is the required suffix for a WarpTweet manifest.
	ManifestExtension = ".wt"

	// ClientTunnelsKind identifies a .wt manifest as client tunnel policy,
	// rather than a server or future WarpTweet manifest kind.
	ClientTunnelsKind = "warptweet.client-tunnels"

	// MaxConfigBytes bounds work performed before a configuration is trusted.
	MaxConfigBytes = 1 << 20
)

// Duration is a human-readable time.Duration encoded as a JSON string, such
// as "500ms" or "30s".
type Duration time.Duration

// UnmarshalJSON decodes a duration from a JSON string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON encodes a duration as a JSON string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Value returns the duration as a standard-library time.Duration.
func (d Duration) Value() time.Duration {
	return time.Duration(d)
}

// Port is a TCP port. Validate rejects its zero value; JSON decoding rejects
// negative, fractional, and out-of-range values.
type Port uint16

// Endpoint is a numeric IP address and TCP port.
type Endpoint struct {
	Address netip.Addr `json:"address"`
	Port    Port       `json:"port"`
}

// Server identifies the SSH server and the Unix account used for the tunnel.
// Host is a persisted locator: an IP literal or a DNS name.
type Server struct {
	Host string `json:"host"`
	Port Port   `json:"port"`
	User string `json:"user"`
}

// Tunnel is one local TCP listener forwarded to a numeric target endpoint.
type Tunnel struct {
	ID     string   `json:"id"`
	Listen Endpoint `json:"listen"`
	Target Endpoint `json:"target"`
}

// Supervision controls bounded exponential restart backoff. The process
// supervisor may add jitter, but it must not exceed MaxBackoff.
type Supervision struct {
	InitialBackoff Duration `json:"initial_backoff"`
	MaxBackoff     Duration `json:"max_backoff"`
}

// Config is the typed representation of a WarpTweet client .wt manifest v2.
// ProfileID is accepted only when it resolves to the immutable
// profile.CurrentID.
type Config struct {
	Kind            string      `json:"kind"`
	SchemaVersion   int         `json:"schema_version"`
	ProfileID       string      `json:"profile_id"`
	SSHBinarySHA256 string      `json:"ssh_binary_sha256"`
	Server          Server      `json:"server"`
	Tunnels         []Tunnel    `json:"tunnels"`
	Supervision     Supervision `json:"supervision"`
}

// Load reads, strictly decodes, and validates one .wt JSON manifest.
func Load(path string) (Config, error) {
	if filepath.Ext(path) != ManifestExtension {
		return Config{}, fmt.Errorf("manifest path %q must use the %q extension", path, ManifestExtension)
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open manifest %q: %w", path, err)
	}
	defer file.Close()

	result, err := Decode(file)
	if err != nil {
		return Config{}, fmt.Errorf("load manifest %q: %w", path, err)
	}
	return result, nil
}

// Decode strictly decodes and validates the JSON content of one .wt manifest
// v2 from reader. Duplicate fields, unknown fields, trailing JSON values,
// invalid UTF-8, and oversized inputs are rejected. Call Load when the
// manifest path is known so the required .wt extension is also enforced.
func Decode(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, fmt.Errorf("decode config: reader is nil")
	}

	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("read config: exceeds %d byte limit", MaxConfigBytes)
	}
	if !utf8.Valid(data) {
		return Config{}, fmt.Errorf("decode config: JSON is not valid UTF-8")
	}
	if err := strictjson.ValidateManifestObjectNames(data); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var result Config
	if err := decoder.Decode(&result); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("decode config: trailing JSON value")
		}
		return Config{}, fmt.Errorf("decode config: trailing data: %w", err)
	}

	if err := canonicalizeServerHost(&result); err != nil {
		return Config{}, err
	}
	if err := Validate(result); err != nil {
		return Config{}, err
	}
	return result, nil
}
