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
	ClientStatusEnrollmentPending = "enrollment_pending"
	ClientStatusActive            = "active"
	ClientStatusRotationPending   = "rotation_pending"
	ClientStatusRevocationPending = "revocation_pending"
	ClientStatusRevoked           = "revoked"

	ManagementTokenBytes = 32
)

// ClientRecord is durable server-side enrollment state for one client. Raw
// management capabilities are never stored here.
type ClientRecord struct {
	ClientID                      string `json:"client_id"`
	TunnelID                      string `json:"tunnel_id"`
	InviteID                      string `json:"invite_id"`
	PublicKey                     string `json:"public_key"`
	PublicKeySHA256               string `json:"public_key_sha256"`
	ManagementTokenSHA256         string `json:"management_token_sha256"`
	Principal                     string `json:"principal"`
	ProfileID                     string `json:"profile_id"`
	ServerAddress                 string `json:"server_address"`
	Status                        string `json:"status"`
	AcceptedAt                    string `json:"accepted_at"`
	RevokedAt                     string `json:"revoked_at,omitempty"`
	Generation                    string `json:"generation,omitempty"`
	PreviousPublicKey             string `json:"previous_public_key,omitempty"`
	PreviousManagementTokenSHA256 string `json:"previous_management_token_sha256,omitempty"`
	PendingPublicKey              string `json:"pending_public_key,omitempty"`
	PendingManagementTokenSHA256  string `json:"pending_management_token_sha256,omitempty"`
	OperationStartedAt            string `json:"operation_started_at,omitempty"`
}

type ManagementRequest struct {
	ClientID            string `json:"client_id"`
	ManagementToken     string `json:"management_token"`
	TunnelID            string `json:"tunnel_id"`
	NewPublicKey        string `json:"new_public_key,omitempty"`
	NextManagementToken string `json:"next_management_token,omitempty"`
}

func GenerateManagementToken() (string, error) {
	raw := make([]byte, ManagementTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate management token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// ValidateManagementToken validates the public wire and persisted capability
// shape without logging or returning the capability itself.
func ValidateManagementToken(token string) error {
	if !isManagementToken(token) {
		return fmt.Errorf("%w: management token must be 64 lowercase hex characters", ErrInvalidInvite)
	}
	return nil
}

func HashManagementToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func PublicKeyDigest(publicKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return hex.EncodeToString(sum[:])
}

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

// RevokeClient persists revocation intent before removing authorization. Exact
// retries authenticated by the previous token remain idempotent.
func RevokeClient(directory string, request ManagementRequest, now time.Time, removeAuthorization func(string) error) (ClientRecord, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
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
	if record.TunnelID != request.TunnelID {
		return ClientRecord{}, fmt.Errorf("%w: tunnel_id mismatch", ErrInvalidInvite)
	}
	if record.Status == ClientStatusRevoked {
		if !managementTokenMatches(record.PreviousManagementTokenSHA256, request.ManagementToken) {
			return ClientRecord{}, fmt.Errorf("%w: management token mismatch", ErrInvalidInvite)
		}
		if removeAuthorization == nil {
			return ClientRecord{}, fmt.Errorf("remove authorization callback is required")
		}
		if err := removeAuthorization(record.PublicKey); err != nil {
			return ClientRecord{}, err
		}
		return record, nil
	}
	if record.Status != ClientStatusActive && record.Status != ClientStatusRevocationPending {
		return ClientRecord{}, fmt.Errorf("%w: client status is %q", ErrInvalidInvite, record.Status)
	}
	if !managementTokenMatches(record.ManagementTokenSHA256, request.ManagementToken) {
		return ClientRecord{}, fmt.Errorf("%w: management token mismatch", ErrInvalidInvite)
	}
	if record.Status == ClientStatusActive {
		record.Status = ClientStatusRevocationPending
		record.OperationStartedAt = now.Format(time.RFC3339Nano)
		if err := writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600); err != nil {
			return ClientRecord{}, err
		}
	}
	if removeAuthorization == nil {
		return ClientRecord{}, fmt.Errorf("remove authorization callback is required")
	}
	if err := removeAuthorization(record.PublicKey); err != nil {
		return ClientRecord{}, err
	}
	burned := make([]byte, ManagementTokenBytes)
	if _, err := rand.Read(burned); err != nil {
		return ClientRecord{}, fmt.Errorf("generate burned management token: %w", err)
	}
	record.PreviousManagementTokenSHA256 = record.ManagementTokenSHA256
	record.ManagementTokenSHA256 = HashManagementToken(hex.EncodeToString(burned))
	record.Status = ClientStatusRevoked
	record.RevokedAt = now.Format(time.RFC3339Nano)
	record.OperationStartedAt = ""
	if err := writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600); err != nil {
		return ClientRecord{}, err
	}
	return record, nil
}

// RotateClientPublicKey persists rotation intent before changing
// authorization. The client selects the next capability, allowing exact
// response-loss retries without transmitting any server-generated secret.
func RotateClientPublicKey(directory string, request ManagementRequest, newPublicKey string, now time.Time, replaceAuthorization func(string, string) error) (ClientRecord, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateManagementRequestShape(request); err != nil {
		return ClientRecord{}, err
	}
	newPublicKey = strings.TrimSpace(newPublicKey)
	if err := validatePublicKeyLine(newPublicKey); err != nil {
		return ClientRecord{}, err
	}
	if !isManagementToken(request.NextManagementToken) {
		return ClientRecord{}, fmt.Errorf("%w: next_management_token must be 64 lowercase hex characters", ErrInvalidInvite)
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
	if record.TunnelID != request.TunnelID {
		return ClientRecord{}, fmt.Errorf("%w: tunnel_id mismatch", ErrInvalidInvite)
	}
	nextHash := HashManagementToken(request.NextManagementToken)
	currentHash := HashManagementToken(request.ManagementToken)

	if record.Status == ClientStatusActive && record.PublicKey == newPublicKey &&
		record.ManagementTokenSHA256 == nextHash && record.PreviousManagementTokenSHA256 == currentHash {
		if replaceAuthorization == nil {
			return ClientRecord{}, fmt.Errorf("replace authorization callback is required")
		}
		if err := replaceAuthorization(record.PreviousPublicKey, newPublicKey); err != nil {
			return ClientRecord{}, err
		}
		return record, nil
	}
	if record.Status != ClientStatusActive && record.Status != ClientStatusRotationPending {
		return ClientRecord{}, fmt.Errorf("%w: client status is %q", ErrInvalidInvite, record.Status)
	}
	if !managementTokenMatches(record.ManagementTokenSHA256, request.ManagementToken) {
		return ClientRecord{}, fmt.Errorf("%w: management token mismatch", ErrInvalidInvite)
	}
	if record.Status == ClientStatusActive {
		record.PendingPublicKey = newPublicKey
		record.PendingManagementTokenSHA256 = nextHash
		record.Status = ClientStatusRotationPending
		record.OperationStartedAt = now.Format(time.RFC3339Nano)
		if err := writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600); err != nil {
			return ClientRecord{}, err
		}
	} else if record.PendingPublicKey != newPublicKey || record.PendingManagementTokenSHA256 != nextHash {
		return ClientRecord{}, fmt.Errorf("%w: rotation retry does not match pending state", ErrInvalidInvite)
	}
	if replaceAuthorization == nil {
		return ClientRecord{}, fmt.Errorf("replace authorization callback is required")
	}
	oldPublicKey := record.PublicKey
	if err := replaceAuthorization(oldPublicKey, newPublicKey); err != nil {
		return ClientRecord{}, err
	}
	record.PreviousPublicKey = oldPublicKey
	record.PreviousManagementTokenSHA256 = record.ManagementTokenSHA256
	record.PublicKey = newPublicKey
	record.PublicKeySHA256 = PublicKeyDigest(newPublicKey)
	record.ManagementTokenSHA256 = nextHash
	record.PendingPublicKey = ""
	record.PendingManagementTokenSHA256 = ""
	record.OperationStartedAt = ""
	record.Status = ClientStatusActive
	record.Generation = now.Format("20060102T150405Z")
	if err := writeJSONAtomic(clientPath(directory, record.ClientID), record, 0o600); err != nil {
		return ClientRecord{}, err
	}
	return record, nil
}

func validateManagementRequestShape(request ManagementRequest) error {
	if request.ClientID == "" || request.ManagementToken == "" || request.TunnelID == "" {
		return fmt.Errorf("%w: client_id, management_token, and tunnel_id are required", ErrInvalidInvite)
	}
	if !isHexID(request.ClientID) {
		return fmt.Errorf("%w: client_id is invalid", ErrInvalidInvite)
	}
	if !isManagementToken(request.ManagementToken) {
		return fmt.Errorf("%w: management_token must be 64 lowercase hex characters", ErrInvalidInvite)
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
	if !managementTokenMatches(record.ManagementTokenSHA256, request.ManagementToken) {
		return fmt.Errorf("%w: management token mismatch", ErrInvalidInvite)
	}
	return nil
}

func managementTokenMatches(wantHash, token string) bool {
	if wantHash == "" || !isManagementToken(token) {
		return false
	}
	got := HashManagementToken(token)
	return subtle.ConstantTimeCompare([]byte(got), []byte(wantHash)) == 1
}

func isManagementToken(token string) bool {
	return len(token) == ManagementTokenBytes*2 && isLowerHexDigest(token)
}

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
