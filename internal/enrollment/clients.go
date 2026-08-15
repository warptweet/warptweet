package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// ClientStatusActive is an authorized enrolled client.
	ClientStatusActive = "active"
	// ClientStatusRevoked is a durably revoked client.
	ClientStatusRevoked = "revoked"

	// ManagementTokenBytes is the raw management token size.
	ManagementTokenBytes = 32
)

// ClientRecord is durable server-side enrollment state for one client.
// It never stores the raw management token.
type ClientRecord struct {
	ClientID                string `json:"client_id"`
	TunnelID                string `json:"tunnel_id"`
	InviteID                string `json:"invite_id"`
	PublicKey               string `json:"public_key"`
	PublicKeySHA256         string `json:"public_key_sha256"`
	ManagementTokenSHA256   string `json:"management_token_sha256"`
	Principal               string `json:"principal"`
	ProfileID               string `json:"profile_id"`
	ServerAddress           string `json:"server_address"`
	Status                  string `json:"status"`
	AcceptedAt              string `json:"accepted_at"`
	RevokedAt               string `json:"revoked_at,omitempty"`
	Generation              string `json:"generation,omitempty"`
	RotatedFromClientID     string `json:"rotated_from_client_id,omitempty"`
}

// ManagementRequest authenticates client-initiated revoke/rotate calls.
type ManagementRequest struct {
	ClientID         string `json:"client_id"`
	ManagementToken  string `json:"management_token"`
	TunnelID         string `json:"tunnel_id"`
	NewPublicKey     string `json:"new_public_key,omitempty"`
}

// GenerateManagementToken returns a fresh client management token (hex).
func GenerateManagementToken() (string, error) {
	raw := make([]byte, ManagementTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate management token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// HashManagementToken returns the durable SHA-256 hex digest of a token.
func HashManagementToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// PublicKeyDigest returns SHA-256 hex of the public key line.
func PublicKeyDigest(publicKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return hex.EncodeToString(sum[:])
}

// StoreClient persists one client record exclusively by client_id.
func StoreClient(directory string, record ClientRecord) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if record.ClientID == "" || !isHexID(record.ClientID) {
		return fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	path := clientPath(directory, record.ClientID)
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("client %q already exists", record.ClientID)
	}
	return writeJSONAtomic(path, record, 0o600)
}

// LoadClient reads one client record.
func LoadClient(directory, clientID string) (ClientRecord, error) {
	if !isHexID(clientID) {
		return ClientRecord{}, fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	contents, err := os.ReadFile(clientPath(directory, clientID))
	if err != nil {
		return ClientRecord{}, err
	}
	var record ClientRecord
	if err := decodeStrictJSON(contents, &record); err != nil {
		return ClientRecord{}, err
	}
	return record, nil
}

// UpdateClient overwrites one existing client record under lock.
func UpdateClient(directory string, record ClientRecord) error {
	if !isHexID(record.ClientID) {
		return fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	unlock, err := lockClient(directory, record.ClientID)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := LoadClient(directory, record.ClientID); err != nil {
		return err
	}
	return writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600)
}

// AuthenticateManagement verifies a management token against a stored client.
func AuthenticateManagement(directory string, request ManagementRequest) (ClientRecord, error) {
	if err := validateManagementRequestShape(request); err != nil {
		return ClientRecord{}, err
	}
	unlock, err := lockClient(directory, request.ClientID)
	if err != nil {
		return ClientRecord{}, err
	}
	defer unlock()

	record, err := LoadClient(directory, request.ClientID)
	if err != nil {
		return ClientRecord{}, fmt.Errorf("%w: unknown client", ErrInvalidInvite)
	}
	if err := authenticateClientRecord(record, request); err != nil {
		return ClientRecord{}, err
	}
	return record, nil
}

// RevokeClient marks a client revoked after management auth.
func RevokeClient(directory string, request ManagementRequest, now time.Time) (ClientRecord, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !isHexID(request.ClientID) {
		return ClientRecord{}, fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	unlock, err := lockClient(directory, request.ClientID)
	if err != nil {
		return ClientRecord{}, err
	}
	defer unlock()

	record, err := LoadClient(directory, request.ClientID)
	if err != nil {
		return ClientRecord{}, fmt.Errorf("%w: unknown client", ErrInvalidInvite)
	}
	if record.Status == ClientStatusRevoked {
		return record, nil
	}
	if err := authenticateClientRecord(record, request); err != nil {
		return ClientRecord{}, err
	}
	record.Status = ClientStatusRevoked
	record.RevokedAt = now.Format(time.RFC3339Nano)
	// Burn the token hash so replay fails closed.
	record.ManagementTokenSHA256 = HashManagementToken(record.ClientID + ":revoked:" + record.RevokedAt)
	if err := writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600); err != nil {
		return ClientRecord{}, err
	}
	return record, nil
}

// RotateClientPublicKey replaces the active public key and issues a new token.
func RotateClientPublicKey(
	directory string,
	request ManagementRequest,
	newPublicKey string,
	now time.Time,
) (ClientRecord, string, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !isHexID(request.ClientID) {
		return ClientRecord{}, "", fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	newPublicKey = strings.TrimSpace(newPublicKey)
	if err := validatePublicKeyLine(newPublicKey); err != nil {
		return ClientRecord{}, "", err
	}

	unlock, err := lockClient(directory, request.ClientID)
	if err != nil {
		return ClientRecord{}, "", err
	}
	defer unlock()

	record, err := LoadClient(directory, request.ClientID)
	if err != nil {
		return ClientRecord{}, "", fmt.Errorf("%w: unknown client", ErrInvalidInvite)
	}
	if err := authenticateClientRecord(record, request); err != nil {
		return ClientRecord{}, "", err
	}

	token, err := GenerateManagementToken()
	if err != nil {
		return ClientRecord{}, "", err
	}
	record.RotatedFromClientID = record.ClientID
	record.PublicKey = newPublicKey
	record.PublicKeySHA256 = PublicKeyDigest(newPublicKey)
	record.ManagementTokenSHA256 = HashManagementToken(token)
	record.Generation = now.Format("20060102T150405Z")
	if err := writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600); err != nil {
		return ClientRecord{}, "", err
	}
	return record, token, nil
}

func validateManagementRequestShape(request ManagementRequest) error {
	if request.ClientID == "" || request.ManagementToken == "" || request.TunnelID == "" {
		return fmt.Errorf("%w: client_id, management_token, and tunnel_id are required", ErrInvalidInvite)
	}
	if !isHexID(request.ClientID) {
		return fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	return nil
}

func authenticateClientRecord(record ClientRecord, request ManagementRequest) error {
	if record.Status != ClientStatusActive {
		return fmt.Errorf("%w: client status is %q", ErrInvalidInvite, record.Status)
	}
	if record.TunnelID != request.TunnelID {
		return fmt.Errorf("%w: tunnel_id mismatch", ErrInvalidInvite)
	}
	want := record.ManagementTokenSHA256
	if want == "" {
		return fmt.Errorf("%w: management token mismatch", ErrInvalidInvite)
	}
	got := HashManagementToken(request.ManagementToken)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("%w: management token mismatch", ErrInvalidInvite)
	}
	return nil
}

// ListClients returns client records.
func ListClients(directory string) ([]ClientRecord, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []ClientRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := LoadClient(directory, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func clientPath(directory, clientID string) string {
	return filepath.Join(directory, clientID+".json")
}

func lockClient(directory, clientID string) (func(), error) {
	if !isHexID(clientID) {
		return nil, fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	return lockPathExclusive(directory, "."+clientID+".lock", "client")
}
