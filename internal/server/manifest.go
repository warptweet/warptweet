package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// ManifestKind prevents a different WarpTweet .wt document from being
	// interpreted as a server-gateway policy.
	ManifestKind = "warptweet.server-gateway"

	// CurrentSchemaVersion is the only server manifest schema accepted by this
	// package. Semantic changes require a new version.
	CurrentSchemaVersion = 1

	// MaxManifestBytes bounds all work performed before manifest content is
	// trusted.
	MaxManifestBytes = 1 << 20
)

// Load reads one server-gateway manifest. WarpTweet manifests use a
// case-sensitive .wt extension so JSON or other files cannot be selected by
// accident.
func Load(path string) (Config, error) {
	if filepath.Ext(path) != ".wt" {
		return Config{}, fmt.Errorf("load server manifest %q: path must end in .wt", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open server manifest %q: %w", path, err)
	}
	defer file.Close()

	config, err := Decode(file)
	if err != nil {
		return Config{}, fmt.Errorf("load server manifest %q: %w", path, err)
	}
	return config, nil
}

// Decode strictly decodes and validates one server-gateway manifest.
// Duplicate or non-canonical field names, unknown fields, trailing JSON
// values, invalid UTF-8, and oversized inputs are rejected.
func Decode(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, fmt.Errorf("decode server manifest: reader is nil")
	}

	data, err := io.ReadAll(io.LimitReader(reader, MaxManifestBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read server manifest: %w", err)
	}
	if len(data) > MaxManifestBytes {
		return Config{}, fmt.Errorf(
			"read server manifest: exceeds %d byte limit",
			MaxManifestBytes,
		)
	}
	if !utf8.Valid(data) {
		return Config{}, fmt.Errorf("decode server manifest: JSON is not valid UTF-8")
	}
	if err := strictjson.ValidateManifestObjectNames(data); err != nil {
		return Config{}, fmt.Errorf("decode server manifest: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode server manifest: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("decode server manifest: trailing JSON value")
		}
		return Config{}, fmt.Errorf("decode server manifest: trailing data: %w", err)
	}

	if err := Validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}
