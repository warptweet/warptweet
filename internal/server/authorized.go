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
	// authorization file. The v1 server policy permits exactly one entry.
	MaxAuthorizedKeysBytes = 8 << 10

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

// ValidateAuthorizedKeys requires one byte-for-byte canonical authorization
// entry produced by RenderAuthorizedKey for config. Blank lines, comments,
// alternate option ordering, and additional client keys are rejected.
func ValidateAuthorizedKeys(config Config, contents []byte) (AuthorizedKeysReport, error) {
	selectedProfile, err := validate(config)
	if err != nil {
		return AuthorizedKeysReport{}, fmt.Errorf("validate authorized keys: %w", err)
	}
	if len(contents) == 0 {
		return AuthorizedKeysReport{}, invalidAuthorizedKey("authorized_keys input is empty")
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
	line := contents[:len(contents)-1]
	if len(line) == 0 || bytes.IndexByte(line, '\r') >= 0 || bytes.IndexByte(line, '\n') >= 0 {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"authorized_keys must contain exactly one LF-terminated entry",
		)
	}
	for index, value := range line {
		if value < 0x20 || value == 0x7f {
			return AuthorizedKeysReport{}, invalidAuthorizedKey(
				"authorized_keys contains a control character at byte %d",
				index,
			)
		}
	}

	prefix := managedAuthorizedKeyPrefix(config, selectedProfile.AuthenticationKeyType)
	suffix := " " + ManagedClientMarker
	text := string(line)
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"authorized_keys entry does not match the canonical managed format",
		)
	}
	blob := strings.TrimSuffix(strings.TrimPrefix(text, prefix), suffix)
	if blob == "" || strings.ContainsAny(blob, " \t") {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"authorized_keys entry contains an invalid public-key blob field",
		)
	}
	if err := sshwire.ValidatePublicKeyBlob(
		blob,
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
	); err != nil {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"validate authorized_keys public-key blob: %v",
			err,
		)
	}
	canonical := renderManagedAuthorizedKey(
		config,
		selectedProfile.AuthenticationKeyType,
		blob,
	)
	if !bytes.Equal(contents, canonical) {
		return AuthorizedKeysReport{}, invalidAuthorizedKey(
			"authorized_keys entry is not byte-for-byte canonical",
		)
	}
	return AuthorizedKeysReport{KeyCount: 1}, nil
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
