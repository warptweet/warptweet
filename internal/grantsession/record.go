package grantsession

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/strictjson"
)

// Record is one durable authenticated session binding.
type Record struct {
	Kind            string `json:"kind"`
	SchemaVersion   int    `json:"schema_version"`
	GrantID         string `json:"grant_id"`
	ClientID        string `json:"client_id"`
	Generation      string `json:"generation"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	KeyBlobSHA256   string `json:"key_blob_sha256"`
	BootID          string `json:"boot_id"`
	PID             int    `json:"pid"`
	StartTime       string `json:"start_time"`
	Exe             string `json:"exe"`
	ConnectionID    string `json:"connection_id"`
	RegisteredAt    string `json:"registered_at"`
	path            string
}

// ProcessIdentity cannot be confused by PID reuse.
type ProcessIdentity struct {
	BootID    string
	PID       int
	StartTime string
	Exe       string
}

func validateRecord(record Record) error {
	if record.Kind != Kind || record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported grant session schema")
	}
	if record.GrantID == "" || record.ClientID == "" || record.Generation == "" {
		return fmt.Errorf("grant session missing grant binding")
	}
	if len(record.PublicKeySHA256) != 64 || !isLowerHex(record.PublicKeySHA256) ||
		len(record.KeyBlobSHA256) != 64 || !isLowerHex(record.KeyBlobSHA256) {
		return fmt.Errorf("grant session missing key binding")
	}
	if record.PID <= 0 {
		return fmt.Errorf("grant session missing process identity")
	}
	if record.BootID == "" || record.StartTime == "" || record.Exe == "" {
		return fmt.Errorf("grant session missing durable process start identity")
	}
	if _, err := grant.ParseUTC(record.RegisteredAt); err != nil {
		return fmt.Errorf("grant session registered_at: %w", err)
	}
	return nil
}

func recordPath(root string, record Record) string {
	id := record.ConnectionID
	if id == "" {
		id = strconv.Itoa(record.PID)
	}
	name := record.ClientID + "-" + record.Generation + "-" + id + ".json"
	return filepath.Join(root, name)
}

func recordFile(root string, record Record) string {
	if record.path != "" {
		return record.path
	}
	return recordPath(root, record)
}

func writeRecord(path string, record Record) error {
	if err := validateRecord(record); err != nil {
		return err
	}
	contents, err := json.Marshal(record)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	if len(contents) == 0 || len(contents) > MaxRecordBytes {
		return fmt.Errorf("grant session document is empty or oversized")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".wt-session-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err := temp.Write(contents); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func readRecord(path string) (Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return Record{}, err
	}
	defer file.Close()
	contents, err := readBounded(file, MaxRecordBytes)
	if err != nil {
		return Record{}, err
	}
	if len(contents) == 0 {
		return Record{}, fmt.Errorf("grant session document is empty or oversized")
	}
	if err := strictjson.RejectDuplicateObjectNames(contents); err != nil {
		return Record{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, err
	}
	if decoder.More() {
		return Record{}, fmt.Errorf("trailing JSON values")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}
