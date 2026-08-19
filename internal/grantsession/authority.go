package grantsession

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grant"
)

// Authority is the serialized grant-session writer and terminator.
type Authority struct {
	Root        string
	Clients     string
	LockPath    string
	ExpectedExe string
	Now         func() time.Time
	Inspect     func(pid int) (ProcessIdentity, error)
	mu          sync.Mutex
	lockFile    *os.File
}

// Register binds a verified key digest to the calling process identity.
func (authority *Authority) Register(pid int, keyBlobSHA256, connectionID string) (Record, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.lock(); err != nil {
		return Record{}, err
	}
	defer authority.unlock()

	identity, err := authority.inspect(pid)
	if err != nil {
		return Record{}, fmt.Errorf("%w: process identity: %v", ErrRejected, err)
	}
	if identity.Exe == "" || !strings.Contains(identity.Exe, "/") {
		return Record{}, fmt.Errorf("%w: process executable path is unavailable", ErrRejected)
	}
	if authority.ExpectedExe != "" {
		if identity.Exe != authority.ExpectedExe {
			return Record{}, fmt.Errorf("%w: process is not the WarpTweet data-plane", ErrRejected)
		}
	} else if !looksLikeWarpTweetSession(identity) {
		return Record{}, fmt.Errorf("%w: process is not the WarpTweet data-plane", ErrRejected)
	}
	record, err := authority.matchingGrant(keyBlobSHA256)
	if err != nil {
		return Record{}, err
	}
	now := authority.now()
	registeredAt, err := grant.FormatUTC(now)
	if err != nil {
		return Record{}, err
	}
	if connectionID == "" {
		connectionID = fmt.Sprintf("%s-%d", record.Generation, pid)
	}
	session := Record{
		Kind:            Kind,
		SchemaVersion:   SchemaVersion,
		GrantID:         record.GrantID,
		ClientID:        record.ClientID,
		Generation:      record.Generation,
		PublicKeySHA256: record.PublicKeySHA256,
		KeyBlobSHA256:   keyBlobSHA256,
		BootID:          identity.BootID,
		PID:             identity.PID,
		StartTime:       identity.StartTime,
		Exe:             identity.Exe,
		ConnectionID:    connectionID,
		RegisteredAt:    registeredAt,
	}
	if err := writeRecord(recordPath(authority.Root, session), session); err != nil {
		return Record{}, fmt.Errorf("%w: persist session: %v", ErrRejected, err)
	}
	return session, nil
}

// Unregister removes sessions for the calling process.
func (authority *Authority) Unregister(pid int) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.lock(); err != nil {
		return err
	}
	defer authority.unlock()
	return authority.clearPID(pid)
}

// Lookup returns durable records for one grant generation.
func (authority *Authority) Lookup(clientID, generation, publicKeySHA256 string) ([]Record, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.listMatching(func(record Record) bool {
		return record.ClientID == clientID && record.Generation == generation && record.PublicKeySHA256 == publicKeySHA256
	})
}

// All returns every durable session record.
func (authority *Authority) All() ([]Record, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.listMatching(func(Record) bool { return true })
}

// Clear removes matching records after termination is proven.
func (authority *Authority) Clear(clientID, generation, publicKeySHA256 string) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.lock(); err != nil {
		return err
	}
	defer authority.unlock()
	entries, err := os.ReadDir(authority.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(authority.Root, entry.Name())
		record, readErr := readRecord(path)
		if readErr != nil {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if record.ClientID != clientID || record.Generation != generation || record.PublicKeySHA256 != publicKeySHA256 {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (authority *Authority) matchingGrant(keyBlobSHA256 string) (enrollment.ClientRecord, error) {
	records, err := enrollment.ListClients(authority.Clients)
	if err != nil {
		return enrollment.ClientRecord{}, fmt.Errorf("%w: list grants: %v", ErrRejected, err)
	}
	var matches []enrollment.ClientRecord
	now := authority.now()
	for _, record := range records {
		digest, err := KeyBlobDigest(record.PublicKey)
		if err != nil || digest != keyBlobSHA256 {
			continue
		}
		switch record.Status {
		case enrollment.ClientStatusActive, enrollment.ClientStatusRotationPending:
		default:
			return enrollment.ClientRecord{}, fmt.Errorf("%w: grant status is %s", ErrRejected, record.Status)
		}
		if record.AuthorizationNotAfter == "" {
			return enrollment.ClientRecord{}, fmt.Errorf("%w: grant missing expiry", ErrRejected)
		}
		notAfter, err := grant.ParseUTC(record.AuthorizationNotAfter)
		if err != nil || grant.ReadyToExpire(notAfter, now) {
			return enrollment.ClientRecord{}, fmt.Errorf("%w: grant is expired", ErrRejected)
		}
		matches = append(matches, record)
	}
	if len(matches) == 0 {
		return enrollment.ClientRecord{}, fmt.Errorf("%w: no active grant for key", ErrRejected)
	}
	if len(matches) != 1 {
		return enrollment.ClientRecord{}, fmt.Errorf("%w: key maps to more than one grant", ErrRejected)
	}
	return matches[0], nil
}

func (authority *Authority) listMatching(keep func(Record) bool) ([]Record, error) {
	entries, err := os.ReadDir(authority.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []Record
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := readRecord(filepath.Join(authority.Root, entry.Name()))
		if err != nil {
			return nil, err
		}
		if keep(record) {
			records = append(records, record)
		}
	}
	return records, nil
}

func (authority *Authority) clearPID(pid int) error {
	records, err := authority.listMatching(func(record Record) bool { return record.PID == pid })
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := os.Remove(recordPath(authority.Root, record)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (authority *Authority) inspect(pid int) (ProcessIdentity, error) {
	if authority.Inspect != nil {
		return authority.Inspect(pid)
	}
	return inspectProcess(pid)
}

func (authority *Authority) now() time.Time {
	if authority.Now != nil {
		return authority.Now().UTC()
	}
	return time.Now().UTC()
}

func (authority *Authority) lock() error {
	if authority.LockPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(authority.LockPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(authority.LockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := flockExclusive(file); err != nil {
		_ = file.Close()
		return err
	}
	authority.lockFile = file
	return nil
}

func (authority *Authority) unlock() {
	if authority.lockFile == nil {
		return
	}
	_ = flockUnlock(authority.lockFile)
	_ = authority.lockFile.Close()
	authority.lockFile = nil
}

var knownSSHKeyTypes = []string{
	"ssh-mldsa44-ed25519@openssh.com",
	"ssh-ed25519",
	"ssh-rsa",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521",
}

// KeyBlobDigest is the canonical digest of one OpenSSH public-key blob.
func KeyBlobDigest(publicKey string) (string, error) {
	fields, err := splitAuthorizedKeyFieldsStrict(strings.TrimSpace(publicKey))
	if err != nil {
		return "", err
	}
	typeIndex := -1
	for i, field := range fields {
		if isKnownSSHKeyType(field) {
			typeIndex = i
			break
		}
	}
	if typeIndex < 0 || typeIndex+1 >= len(fields) {
		return "", fmt.Errorf("public key is unparsable")
	}
	raw, err := base64.StdEncoding.DecodeString(fields[typeIndex+1])
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func isKnownSSHKeyType(value string) bool {
	for _, known := range knownSSHKeyTypes {
		if value == known {
			return true
		}
	}
	return false
}

func splitAuthorizedKeyFields(line string) []string {
	fields, err := splitAuthorizedKeyFieldsStrict(line)
	if err != nil {
		return nil
	}
	return fields
}

func splitAuthorizedKeyFieldsStrict(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	inQuote := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' && inQuote {
			escaped = true
			current.WriteByte(c)
			continue
		}
		switch {
		case c == '"':
			inQuote = !inQuote
			current.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQuote:
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if inQuote || escaped {
		return nil, fmt.Errorf("unterminated quoted authorized_keys field")
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields, nil
}
