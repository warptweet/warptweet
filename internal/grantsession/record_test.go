package grantsession

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validTestRecord() Record {
	return Record{
		Kind:            Kind,
		SchemaVersion:   SchemaVersion,
		GrantID:         "grant-1",
		ClientID:        "client-1",
		Generation:      "20260816T120000Z",
		PublicKeySHA256: strings.Repeat("ab", 32),
		KeyBlobSHA256:   strings.Repeat("cd", 32),
		BootID:          "boot-1",
		PID:             42,
		StartTime:       "99",
		Exe:             "/opt/warptweet/libexec/openssh/libexec/sshd-session",
		ConnectionID:    "conn-1",
		RegisteredAt:    "2026-08-16T12:00:00Z",
	}
}

func TestValidateRecordRejectsNonLowerHexKeyBindings(t *testing.T) {
	t.Parallel()

	record := validTestRecord()
	if err := validateRecord(record); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	record.PublicKeySHA256 = strings.ToUpper(record.PublicKeySHA256)
	if err := validateRecord(record); err == nil {
		t.Fatal("accepted uppercase public_key_sha256")
	}
	record = validTestRecord()
	record.KeyBlobSHA256 = strings.ToUpper(record.KeyBlobSHA256)
	if err := validateRecord(record); err == nil {
		t.Fatal("accepted uppercase key_blob_sha256")
	}
	record = validTestRecord()
	record.KeyBlobSHA256 = strings.Repeat("CG", 32)
	if err := validateRecord(record); err == nil {
		t.Fatal("accepted non-hex key_blob_sha256")
	}
	record = validTestRecord()
	record.PublicKeySHA256 = ""
	record.KeyBlobSHA256 = ""
	if err := validateRecord(record); err == nil {
		t.Fatal("accepted missing key bindings")
	}
}

func TestWriteRecordUsesGroupReadableMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session.json")
	if err := writeRecord(path, validTestRecord()); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("session record mode=%o want 0640", info.Mode().Perm())
	}
}

func TestWriteRecordRejectsOversizedSerializedContents(t *testing.T) {
	t.Parallel()

	record := validTestRecord()
	record.Exe = strings.Repeat("x", MaxRecordBytes)
	if err := writeRecord(filepath.Join(t.TempDir(), "session.json"), record); err == nil {
		t.Fatal("accepted oversized record")
	}
}

func TestReadRecordEnforcesMaxRecordBytes(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session.json")
	record := validTestRecord()
	record.Exe = strings.Repeat("x", MaxRecordBytes)
	contents, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(contents, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(path); err == nil {
		t.Fatal("accepted oversized valid record")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(path); err == nil {
		t.Fatal("accepted empty file")
	}
}
