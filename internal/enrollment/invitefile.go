package enrollment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	// InviteFileExtension is the operator-facing invite document extension.
	// Type lives in the extension; basenames stay human-oriented labels.
	InviteFileExtension = ".wtinvite"

	// MaxInviteLabelBytes bounds sanitized invite basenames.
	MaxInviteLabelBytes = 48

	// InviteIDPathPrefixBytes is the invite_id hex prefix used when a default
	// basename collides (four characters; six on a second collision).
	InviteIDPathPrefixBytes = 4
)

// ErrInvitePathCollision identifies exclusive-create failures after disambiguation.
var ErrInvitePathCollision = errors.New("invite path already exists")

// SanitizeInviteLabel normalizes a hostname or --name value for invite basenames
// and client labels: lowercase ASCII, [a-z0-9-], collapsed separators, max 48,
// empty → "host". Leading digits get an "n" prefix so the label can also serve
// as a tunnel id.
func SanitizeInviteLabel(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "host"
	}
	var b strings.Builder
	lastHyphen := false
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastHyphen = false
		default:
			if unicode.IsSpace(r) || r == '_' || r == '.' || r == '-' {
				if b.Len() > 0 && !lastHyphen {
					b.WriteByte('-')
					lastHyphen = true
				}
			}
		}
	}
	label := strings.Trim(b.String(), "-")
	if label == "" {
		return "host"
	}
	if label[0] >= '0' && label[0] <= '9' {
		label = "n" + label
	}
	if len(label) > MaxInviteLabelBytes {
		label = strings.Trim(label[:MaxInviteLabelBytes], "-")
		if label == "" {
			return "host"
		}
		if label[0] >= '0' && label[0] <= '9' {
			label = "n" + label
			if len(label) > MaxInviteLabelBytes {
				label = label[:MaxInviteLabelBytes]
			}
		}
	}
	return label
}

// InviteFileName returns the default basename for a label, without directory.
func InviteFileName(label string) string {
	return SanitizeInviteLabel(label) + InviteFileExtension
}

// InviteCollisionFileName returns label-<idPrefix>.wtinvite using the first
// prefixLen hex characters of inviteID (lowercase).
func InviteCollisionFileName(label, inviteID string, prefixLen int) (string, error) {
	label = SanitizeInviteLabel(label)
	id := strings.ToLower(strings.TrimSpace(inviteID))
	if prefixLen < InviteIDPathPrefixBytes {
		prefixLen = InviteIDPathPrefixBytes
	}
	if len(id) < prefixLen {
		return "", fmt.Errorf("%w: invite_id too short for path disambiguation", ErrInvalidInvite)
	}
	for _, r := range id[:prefixLen] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", fmt.Errorf("%w: invite_id prefix must be hex", ErrInvalidInvite)
		}
	}
	return label + "-" + id[:prefixLen] + InviteFileExtension, nil
}

// WriteInviteFile writes invite JSON exclusively under directory.
// First try is <label>.wtinvite. On collision, try label-<id4>.wtinvite, then
// label-<id6>.wtinvite. Does not overwrite existing paths.
func WriteInviteFile(directory, label, inviteID string, contents []byte) (string, error) {
	if directory == "" {
		return "", errors.New("invite directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	label = SanitizeInviteLabel(label)
	candidates := []string{InviteFileName(label)}
	if name, err := InviteCollisionFileName(label, inviteID, InviteIDPathPrefixBytes); err == nil {
		candidates = append(candidates, name)
	}
	if name, err := InviteCollisionFileName(label, inviteID, InviteIDPathPrefixBytes+2); err == nil {
		candidates = append(candidates, name)
	}
	var lastErr error
	for _, name := range candidates {
		path := filepath.Join(directory, name)
		if err := writeInviteExclusive(path, contents); err != nil {
			if errors.Is(err, os.ErrExist) {
				lastErr = err
				continue
			}
			return "", err
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return path, nil
		}
		return abs, nil
	}
	if lastErr == nil {
		lastErr = ErrInvitePathCollision
	}
	return "", fmt.Errorf("%w: pass --out or remove the existing invite file: %v", ErrInvitePathCollision, lastErr)
}

// WriteInviteFileExact writes invite JSON to an exact path with O_EXCL.
// Parent directories must already exist. Never auto-suffixes.
func WriteInviteFileExact(path string, contents []byte) (string, error) {
	if path == "" {
		return "", errors.New("invite path is required")
	}
	if filepath.Ext(path) != InviteFileExtension {
		return "", fmt.Errorf("invite path must end in %s", InviteFileExtension)
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("invite parent directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("invite parent %q is not a directory", parent)
	}
	if err := writeInviteExclusive(path, contents); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%w: %s", ErrInvitePathCollision, path)
		}
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return abs, nil
}

func writeInviteExclusive(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(contents); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
