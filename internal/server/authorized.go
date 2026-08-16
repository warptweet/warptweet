package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"warptweet.com/warptweet/internal/sshwire"
)

const (
	// MaxAuthorizedKeyInputBytes bounds enrollment work and remains within
	// OpenSSH's authorized_keys line-size limit.
	MaxAuthorizedKeyInputBytes = 8 << 10
	// MaxAuthorizedKeysBytes bounds validation of the complete product-owned
	// authorization file while permitting a managed set of enrolled clients.
	MaxAuthorizedKeysBytes = 1 << 20

	// ManagedClientMarker is the only comment accepted on a managed client
	// authorization entry.
	ManagedClientMarker = "warptweet-managed-client"
)

// ErrInvalidAuthorizedKey identifies public-key input that is unsafe to place
// in WarpTweet's managed authorized_keys file.
var ErrInvalidAuthorizedKey = errors.New("invalid WarpTweet authorized key")

// AuthorizedKeysReport records the non-secret authorization facts proven by
// ValidateAuthorizedKeys.
type AuthorizedKeysReport struct {
	KeyCount int
}

// RenderAuthorizedKey validates one plain public-key line and adds the
// defense-in-depth restrictions that bind it to Config.Target. Any input
// comment is intentionally replaced with WarpTweet's stable managed marker.
func RenderAuthorizedKey(config Config, publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return nil, invalidAuthorizedKey("input is empty")
	}
	if len(publicKey) > MaxAuthorizedKeyInputBytes {
		return nil, invalidAuthorizedKey(
			"input is %d bytes, limit is %d",
			len(publicKey),
			MaxAuthorizedKeyInputBytes,
		)
	}

	selectedProfile, err := validate(config)
	if err != nil {
		return nil, fmt.Errorf("render authorized key: %w", err)
	}

	line, err := onePublicKeyLine(publicKey)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return nil, invalidAuthorizedKey("plain public-key line must contain a key type and blob")
	}
	if fields[0] != selectedProfile.AuthenticationKeyType {
		return nil, invalidAuthorizedKey(
			"key type %q does not match required type %q; options are not accepted",
			fields[0],
			selectedProfile.AuthenticationKeyType,
		)
	}
	if err := sshwire.ValidatePublicKeyBlob(
		fields[1],
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
	); err != nil {
		return nil, invalidAuthorizedKey("validate public-key blob: %v", err)
	}

	return renderManagedAuthorizedKey(config, selectedProfile.AuthenticationKeyType, fields[1]), nil
}

// ValidateAuthorizedKeys requires zero or more byte-for-byte canonical,
// distinct authorization entries produced by RenderAuthorizedKey for config.
// An empty file is the valid pre-enrollment state.
func ValidateAuthorizedKeys(config Config, contents []byte) (AuthorizedKeysReport, error) {
	selectedProfile, err := validate(config)
	if err != nil {
		return AuthorizedKeysReport{}, fmt.Errorf("validate authorized keys: %w", err)
	}
	if len(contents) == 0 {
		return AuthorizedKeysReport{KeyCount: 0}, nil
	}
	if len(contents) > MaxAuthorizedKeysBytes {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"authorized_keys input is %d bytes, limit is %d",
			len(contents),
			MaxAuthorizedKeysBytes,
		)
	}
	if contents[len(contents)-1] != '\n' {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"authorized_keys entry must end with exactly one LF",
		)
	}
	prefix := managedAuthorizedKeyPrefix(config, selectedProfile.AuthenticationKeyType)
	suffix := " " + ManagedClientMarker
	lines := bytes.Split(contents[:len(contents)-1], []byte{'\n'})
	seen := make(map[string]struct{}, len(lines))
	for lineIndex, line := range lines {
		if len(line) == 0 || len(line) > MaxAuthorizedKeyInputBytes || bytes.IndexByte(line, '\r') >= 0 {
			return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys line %d has invalid length or terminator", lineIndex+1)
		}
		for byteIndex, value := range line {
			if value < 0x20 || value == 0x7f {
				return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys line %d contains a control character at byte %d", lineIndex+1, byteIndex)
			}
		}
		text := string(line)
		if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
			return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys line %d does not match the canonical managed format", lineIndex+1)
		}
		blob := strings.TrimSuffix(strings.TrimPrefix(text, prefix), suffix)
		if blob == "" || strings.ContainsAny(blob, " \t") {
			return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys line %d contains an invalid public-key blob field", lineIndex+1)
		}
		if _, duplicate := seen[blob]; duplicate {
			return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys line %d duplicates an earlier client key", lineIndex+1)
		}
		seen[blob] = struct{}{}
		if err := sshwire.ValidatePublicKeyBlob(blob, selectedProfile.AuthenticationKeyType, selectedProfile.RawPublicKeyBytes); err != nil {
			return AuthorizedKeysReport{}, invalidAuthorizedKey("validate authorized_keys line %d public-key blob: %v", lineIndex+1, err)
		}
		canonical := renderManagedAuthorizedKey(config, selectedProfile.AuthenticationKeyType, blob)
		if len(canonical) == 0 || canonical[len(canonical)-1] != '\n' || !bytes.Equal(line, canonical[:len(canonical)-1]) {
			return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys line %d is not byte-for-byte canonical", lineIndex+1)
		}
	}
	return AuthorizedKeysReport{KeyCount: len(lines)}, nil
}

func renderManagedAuthorizedKey(config Config, algorithm, blob string) []byte {
	return []byte(managedAuthorizedKeyPrefix(config, algorithm) + blob + " " + ManagedClientMarker + "\n")
}

func managedAuthorizedKeyPrefix(config Config, algorithm string) string {
	target := netip.AddrPortFrom(
		canonicalAddress(config.Target.Address),
		uint16(config.Target.Port),
	).String()
	return fmt.Sprintf(
		"restrict,port-forwarding,permitopen=\"%s\" %s ",
		target,
		algorithm,
	)
}

func onePublicKeyLine(input []byte) ([]byte, error) {
	line := input
	if bytes.HasSuffix(line, []byte{'\n'}) {
		line = line[:len(line)-1]
		if bytes.HasSuffix(line, []byte{'\r'}) {
			line = line[:len(line)-1]
		}
	}
	if len(line) == 0 {
		return nil, invalidAuthorizedKey("public-key line is empty")
	}
	if line[0] == ' ' || line[0] == '\t' || line[len(line)-1] == ' ' || line[len(line)-1] == '\t' {
		return nil, invalidAuthorizedKey("leading or trailing whitespace is not accepted")
	}
	for index, value := range line {
		switch {
		case value == '\r' || value == '\n':
			return nil, invalidAuthorizedKey("input must contain exactly one public-key line")
		case value < 0x20 && value != '\t' || value == 0x7f:
			return nil, invalidAuthorizedKey("control character at byte %d", index)
		}
	}
	return line, nil
}

func invalidAuthorizedKey(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidAuthorizedKey, fmt.Sprintf(format, args...))
}
