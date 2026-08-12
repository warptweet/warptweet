// Package knownhosts renders WarpTweet-managed OpenSSH host-key pins.
package knownhosts

import (
	"bytes"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/sshwire"
)

const (
	// MaxPublicKeyLineBytes bounds all work performed on an untrusted public-key
	// line, including its optional terminal LF and discarded comment.
	MaxPublicKeyLineBytes = 8 << 10

	// ManagedHostComment identifies entries produced by RenderManagedHost.
	ManagedHostComment = "warptweet-managed-host"
)

// ErrInvalidHostPublicKey identifies input that is unsafe to render into a
// WarpTweet-managed known_hosts file.
var ErrInvalidHostPublicKey = errors.New("invalid WarpTweet host public key")

// RenderManagedHost validates one plain OpenSSH public-key line and renders a
// canonical known_hosts entry for tunnelID. The input may have one terminal LF
// and an untrusted comment; the comment is always discarded. Options,
// additional lines, control characters, and non-profile keys are rejected.
func RenderManagedHost(tunnelID string, publicKey []byte) ([]byte, error) {
	if err := config.ValidateTunnelID(tunnelID); err != nil {
		return nil, fmt.Errorf("render managed host: %w", err)
	}
	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		return nil, fmt.Errorf("render managed host: load immutable profile: %w", err)
	}

	algorithm, encoded, err := parsePublicKeyLine(publicKey)
	if err != nil {
		return nil, err
	}
	if algorithm != selectedProfile.AuthenticationKeyType {
		return nil, invalidHostPublicKey(
			"outer key type %q does not match required type %q; options are not accepted",
			algorithm,
			selectedProfile.AuthenticationKeyType,
		)
	}
	if err := sshwire.ValidatePublicKeyBlob(
		encoded,
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
	); err != nil {
		return nil, invalidHostPublicKey("validate public-key blob: %v", err)
	}

	result := fmt.Sprintf(
		"warptweet-%s %s %s %s\n",
		tunnelID,
		selectedProfile.AuthenticationKeyType,
		encoded,
		ManagedHostComment,
	)
	return []byte(result), nil
}

func parsePublicKeyLine(input []byte) (string, string, error) {
	if len(input) == 0 {
		return "", "", invalidHostPublicKey("input is empty")
	}
	if len(input) > MaxPublicKeyLineBytes {
		return "", "", invalidHostPublicKey(
			"input is %d bytes, limit is %d",
			len(input),
			MaxPublicKeyLineBytes,
		)
	}
	if !utf8.Valid(input) {
		return "", "", invalidHostPublicKey("input is not valid UTF-8")
	}

	line := input
	if line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 {
		return "", "", invalidHostPublicKey("public-key line is empty")
	}
	if line[0] == ' ' || line[len(line)-1] == ' ' {
		return "", "", invalidHostPublicKey("leading or trailing whitespace is not accepted")
	}
	for index, character := range string(line) {
		if unicode.IsControl(character) {
			return "", "", invalidHostPublicKey("control character at byte %d", index)
		}
	}

	separator := bytes.IndexByte(line, ' ')
	if separator <= 0 {
		return "", "", invalidHostPublicKey("plain public-key line must contain a key type and blob")
	}
	algorithm := string(line[:separator])
	remainder := line[separator+1:]
	for len(remainder) > 0 && remainder[0] == ' ' {
		remainder = remainder[1:]
	}
	if len(remainder) == 0 {
		return "", "", invalidHostPublicKey("plain public-key line must contain a blob")
	}

	encoded := remainder
	if commentSeparator := bytes.IndexByte(remainder, ' '); commentSeparator >= 0 {
		encoded = remainder[:commentSeparator]
	}
	if len(encoded) == 0 {
		return "", "", invalidHostPublicKey("plain public-key line must contain a blob")
	}
	return algorithm, string(encoded), nil
}

func invalidHostPublicKey(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidHostPublicKey, fmt.Sprintf(format, arguments...))
}
