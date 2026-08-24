// Package enrollment defines single-use server invite authorizations for
// managed client bootstrap. A .wtinvite is a confidential, short-lived,
// single-use bearer. Transfer it over an authenticated channel and delete it
// after consumption or expiry. Invites never carry private keys.
package enrollment

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/locator"
	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// KindInvite is the invite document kind.
	KindInvite = "warptweet.invite"
	// CurrentSchemaVersion is the only supported invite schema.
	// Schema 2 is rejected. There is no decoder for prior numbers.
	CurrentSchemaVersion = 3
	// DefaultTTL is the maximum invite lifetime.
	DefaultTTL = 15 * time.Minute
	// MaxInviteBytes bounds invite JSON.
	MaxInviteBytes = 16 << 10
	// NonceBytes is the invite nonce size.
	NonceBytes = 16
)

// ErrInvalidInvite identifies invite documents that fail closed.
var ErrInvalidInvite = errors.New("invalid WarpTweet invite")

// InviteDial is the published data-plane locator.
type InviteDial struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// InviteEnrollment is the published enrollment locator and SPKI pin.
type InviteEnrollment struct {
	Host          string `json:"host"`
	Port          uint16 `json:"port"`
	TLSSPKISHA256 string `json:"tls_spki_sha256"`
}

// Invite is the canonical enrollment authorization carried to a client.
// It contains no private-key material and no bind addresses.
type Invite struct {
	Kind                         string           `json:"kind"`
	SchemaVersion                int              `json:"schema_version"`
	InviteID                     string           `json:"invite_id"`
	ClientName                   string           `json:"client_name"`
	Data                         InviteDial       `json:"data"`
	Enrollment                   InviteEnrollment `json:"enrollment"`
	PublishedEndpointGeneration  uint64           `json:"published_endpoint_generation"`
	TargetAddress                string           `json:"target_address"`
	TargetPort                   uint16           `json:"target_port"`
	Principal                    string           `json:"principal"`
	ProfileID                    string           `json:"profile_id"`
	ArtifactProfileID            string           `json:"artifact_profile_id"`
	HostPublicKey                string           `json:"host_public_key"`
	IssuedAt                     string           `json:"issued_at"`
	ExpiresAt                    string           `json:"expires_at"`
	AuthorizationDurationSeconds int64            `json:"authorization_duration_seconds"`
	Nonce                        string           `json:"nonce"`
}

// Record is durable server-side invite state.
type Record struct {
	Invite
	Status     string `json:"status"`
	ConsumedAt string `json:"consumed_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
}

const (
	StatusIssued    = "issued"
	StatusConsumed  = "consumed"
	StatusCancelled = "cancelled"
	StatusRevoked   = "revoked"
	StatusExpired   = "expired"
)

// CreateInput is the operator-facing invite request.
type CreateInput struct {
	ClientName                          string
	DataHost                            string
	DataPort                            uint16
	EnrollmentHost                      string
	EnrollmentPort                      uint16
	EnrollmentTLSSPKISHA256             string
	PublishedEndpointGeneration         uint64
	TargetAddress                       netip.Addr
	TargetPort                          uint16
	Principal                           string
	ProfileID                           string
	ArtifactProfileID                   string
	HostPublicKey                       string
	TTL                                 time.Duration
	AuthorizationDurationSeconds        int64
	MaximumAuthorizationDurationSeconds int64
	Now                                 time.Time
}

// Create builds one single-use invite and its durable record.
func Create(input CreateInput) (Invite, Record, error) {
	if err := validateCreateInput(input); err != nil {
		return Invite{}, Record{}, err
	}
	ttl := input.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > DefaultTTL {
		return Invite{}, Record{}, fmt.Errorf("%w: ttl exceeds %s", ErrInvalidInvite, DefaultTTL)
	}
	policy := grant.InstalledDefault()
	if input.MaximumAuthorizationDurationSeconds != 0 {
		policy.MaximumAuthorizationDurationSeconds = input.MaximumAuthorizationDurationSeconds
	}
	authorizationSeconds, err := grant.ResolveDuration(policy, input.AuthorizationDurationSeconds)
	if err != nil {
		return Invite{}, Record{}, fmt.Errorf("%w: %v", ErrInvalidInvite, err)
	}
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return Invite{}, Record{}, fmt.Errorf("generate invite nonce: %w", err)
	}
	inviteID := make([]byte, 16)
	if _, err := rand.Read(inviteID); err != nil {
		return Invite{}, Record{}, fmt.Errorf("generate invite id: %w", err)
	}

	dataHost, err := canonicalInviteHost(input.DataHost)
	if err != nil {
		return Invite{}, Record{}, fmt.Errorf("%w: data host: %v", ErrInvalidInvite, err)
	}
	enrollHost, err := canonicalInviteHost(input.EnrollmentHost)
	if err != nil {
		return Invite{}, Record{}, fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	enrollPort := input.EnrollmentPort
	if enrollPort == 0 {
		enrollPort = DefaultEnrollmentPort
	}
	invite := Invite{
		Kind:          KindInvite,
		SchemaVersion: CurrentSchemaVersion,
		InviteID:      hex.EncodeToString(inviteID),
		ClientName:    input.ClientName,
		Data: InviteDial{
			Host: dataHost,
			Port: input.DataPort,
		},
		Enrollment: InviteEnrollment{
			Host:          enrollHost,
			Port:          enrollPort,
			TLSSPKISHA256: strings.TrimSpace(input.EnrollmentTLSSPKISHA256),
		},
		PublishedEndpointGeneration:  input.PublishedEndpointGeneration,
		TargetAddress:                input.TargetAddress.String(),
		TargetPort:                   input.TargetPort,
		Principal:                    input.Principal,
		ProfileID:                    input.ProfileID,
		ArtifactProfileID:            input.ArtifactProfileID,
		HostPublicKey:                strings.TrimSpace(input.HostPublicKey),
		IssuedAt:                     now.Format(time.RFC3339Nano),
		ExpiresAt:                    now.Add(ttl).Format(time.RFC3339Nano),
		AuthorizationDurationSeconds: authorizationSeconds,
		Nonce:                        hex.EncodeToString(nonce),
	}
	if err := validateInviteShape(invite); err != nil {
		return Invite{}, Record{}, err
	}
	return invite, Record{Invite: invite, Status: StatusIssued}, nil
}

// Store persists one invite record under the invites directory.
func Store(directory string, record Record) error {
	if !isHexID(record.InviteID) {
		return fmt.Errorf("%w: invite_id is invalid", ErrInvalidInvite)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := recordPath(directory, record.InviteID)
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("invite %q already exists", record.InviteID)
	}
	blob, err := Encode(record.Invite)
	if err != nil {
		return err
	}
	return storeIssuedAtomic(directory, record, blob)
}

func storeIssuedAtomic(directory string, record Record, blob []byte) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp(directory, ".wt-invite-tx-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tempDir) }()
	recordPathTemp := filepath.Join(tempDir, record.InviteID+".json")
	blobPathTemp := filepath.Join(tempDir, record.InviteID+".wtinvite")
	if err := writeJSONAtomic(recordPathTemp, record, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(blobPathTemp, append(append([]byte(nil), blob...), '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(recordPathTemp, recordPath(directory, record.InviteID)); err != nil {
		return err
	}
	destBlob := filepath.Join(directory, record.InviteID+".wtinvite")
	if err := os.Rename(blobPathTemp, destBlob); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// IssuedBlobPath is the durable transferable invite next to the record.
func IssuedBlobPath(directory, inviteID string) string {
	return filepath.Join(directory, inviteID+".wtinvite")
}

// LoadIssuedBlob returns the durable transferable bytes for an invite.
func LoadIssuedBlob(directory, inviteID string) ([]byte, error) {
	if !isHexID(inviteID) {
		return nil, fmt.Errorf("%w: invite_id is invalid", ErrInvalidInvite)
	}
	contents, err := os.ReadFile(IssuedBlobPath(directory, inviteID))
	if err == nil {
		return bytes.TrimSuffix(contents, []byte("\n")), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	record, loadErr := Load(directory, inviteID)
	if loadErr != nil {
		return nil, err
	}
	return Encode(record.Invite)
}

// UnusedIssuedForGeneration returns issued, unconsumed invites for generation.
func UnusedIssuedForGeneration(directory string, generation uint64) ([]Record, error) {
	records, err := List(directory)
	if err != nil {
		return nil, err
	}
	var issued []Record
	for _, record := range records {
		if record.Status == StatusIssued && record.PublishedEndpointGeneration == generation {
			issued = append(issued, record)
		}
	}
	return issued, nil
}

// IsHexID reports whether value is a bounded hexadecimal identifier.
func IsHexID(value string) bool {
	return isHexID(value)
}

// Load reads one invite record.
func Load(directory, inviteID string) (Record, error) {
	if !isHexID(inviteID) {
		return Record{}, fmt.Errorf("%w: invite_id is invalid", ErrInvalidInvite)
	}
	contents, err := os.ReadFile(recordPath(directory, inviteID))
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := decodeStrictJSON(contents, &record); err != nil {
		return Record{}, err
	}
	if err := canonicalizeStoredInvite(&record.Invite); err != nil {
		return Record{}, err
	}
	return record, nil
}

func decodeStrictJSON(raw []byte, destination any) error {
	if err := strictjson.RejectDuplicateObjectNames(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing JSON values")
	}
	return nil
}

// Consume marks an issued invite consumed. Reuse fails closed.
func Consume(directory, inviteID, clientID string, now time.Time) (Record, error) {
	record, err := Load(directory, inviteID)
	if err != nil {
		return Record{}, err
	}
	if record.Status != StatusIssued {
		return Record{}, fmt.Errorf("%w: invite status is %q", ErrInvalidInvite, record.Status)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expires, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil {
		return Record{}, err
	}
	if !now.Before(expires) {
		record.Status = StatusExpired
		_ = writeJSONAtomic(recordPath(directory, inviteID), record, 0o600)
		return Record{}, fmt.Errorf("%w: invite expired", ErrInvalidInvite)
	}
	record.Status = StatusConsumed
	record.ConsumedAt = now.Format(time.RFC3339Nano)
	record.ClientID = clientID
	if err := writeJSONAtomic(recordPath(directory, inviteID), record, 0o600); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Cancel marks an unconsumed invite cancelled. It does not revoke a grant.
func Cancel(directory, inviteID string, now time.Time) (Record, error) {
	unlock, err := lockInvite(directory, inviteID)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	record, err := Load(directory, inviteID)
	if err != nil {
		return Record{}, err
	}
	if record.Status == StatusCancelled {
		return record, nil
	}
	if record.Status == StatusConsumed || record.Status == StatusRevoked {
		return Record{}, fmt.Errorf("invite %s is %s; cancel applies only to unconsumed invitations", inviteID, record.Status)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.Status = StatusCancelled
	record.RevokedAt = now.Format(time.RFC3339Nano)
	if err := writeJSONAtomic(recordPath(directory, inviteID), record, 0o600); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Revoke marks a consumed invite revoked after the grant itself is revoked.
func Revoke(directory, inviteID string, now time.Time) (Record, error) {
	record, err := Load(directory, inviteID)
	if err != nil {
		return Record{}, err
	}
	if record.Status == StatusRevoked {
		return record, nil
	}
	if record.Status == StatusIssued || record.Status == StatusCancelled {
		return Record{}, fmt.Errorf("invite %s is %s; revoke applies only after consumption", inviteID, record.Status)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.Status = StatusRevoked
	record.RevokedAt = now.Format(time.RFC3339Nano)
	if err := writeJSONAtomic(recordPath(directory, inviteID), record, 0o600); err != nil {
		return Record{}, err
	}
	return record, nil
}

// List returns invite records in directory order.
func List(directory string) ([]Record, error) {
	entries, err := os.ReadDir(directory)
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
		record, err := Load(directory, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// Encode returns canonical invite JSON for operator transfer.
func Encode(invite Invite) ([]byte, error) {
	return json.Marshal(invite)
}

func validateCreateInput(input CreateInput) error {
	if input.ClientName == "" || !isSafeName(input.ClientName) {
		return fmt.Errorf("%w: client name is required and must be alphanumeric with ._- ", ErrInvalidInvite)
	}
	if _, err := canonicalInviteHost(input.DataHost); err != nil {
		return fmt.Errorf("%w: data host: %v", ErrInvalidInvite, err)
	}
	if _, err := canonicalInviteHost(input.EnrollmentHost); err != nil {
		return fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	if !input.TargetAddress.IsValid() || input.TargetAddress.IsUnspecified() || input.TargetAddress.Zone() != "" {
		return fmt.Errorf("%w: target address must be a concrete unzoned IP", ErrInvalidInvite)
	}
	if input.DataPort == 0 || input.TargetPort == 0 {
		return fmt.Errorf("%w: ports must be nonzero", ErrInvalidInvite)
	}
	if input.PublishedEndpointGeneration == 0 {
		return fmt.Errorf("%w: published_endpoint_generation must be at least 1", ErrInvalidInvite)
	}
	dataKey, err := dialLocatorKey(input.DataHost, input.DataPort)
	if err != nil {
		return fmt.Errorf("%w: data host: %v", ErrInvalidInvite, err)
	}
	enrollPort := input.EnrollmentPort
	if enrollPort == 0 {
		enrollPort = DefaultEnrollmentPort
	}
	enrollKey, err := dialLocatorKey(input.EnrollmentHost, enrollPort)
	if err != nil {
		return fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	if dataKey == enrollKey {
		return fmt.Errorf("%w: data and enrollment locators must not share the same canonical host:port", ErrInvalidInvite)
	}
	if input.Principal == "" || input.ProfileID == "" || input.ArtifactProfileID == "" {
		return fmt.Errorf("%w: principal, profile_id, and artifact_profile_id are required", ErrInvalidInvite)
	}
	if strings.TrimSpace(input.HostPublicKey) == "" || strings.ContainsAny(input.HostPublicKey, "\r\n\x00") {
		return fmt.Errorf("%w: host public key is required and must be one line", ErrInvalidInvite)
	}
	if !isLowerHexDigest(input.EnrollmentTLSSPKISHA256) {
		return fmt.Errorf("%w: enrollment tls_spki_sha256 must be a lowercase SHA-256 digest", ErrInvalidInvite)
	}
	return nil
}

func validateInviteShape(invite Invite) error {
	if invite.Kind != KindInvite || invite.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("%w: unsupported kind or schema", ErrInvalidInvite)
	}
	if invite.InviteID == "" || invite.ClientName == "" || invite.Nonce == "" {
		return fmt.Errorf("%w: required fields missing", ErrInvalidInvite)
	}
	if !isHexID(invite.InviteID) {
		return fmt.Errorf("%w: invite_id is invalid", ErrInvalidInvite)
	}
	if invite.PublishedEndpointGeneration == 0 {
		return fmt.Errorf("%w: published_endpoint_generation must be at least 1", ErrInvalidInvite)
	}
	if _, err := canonicalInviteHost(invite.Data.Host); err != nil {
		return fmt.Errorf("%w: data host: %v", ErrInvalidInvite, err)
	}
	if _, err := canonicalInviteHost(invite.Enrollment.Host); err != nil {
		return fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	if _, err := netip.ParseAddr(invite.TargetAddress); err != nil {
		return fmt.Errorf("%w: target address: %v", ErrInvalidInvite, err)
	}
	if invite.Data.Port == 0 || invite.TargetPort == 0 || invite.Enrollment.Port == 0 {
		return fmt.Errorf("%w: ports must be nonzero", ErrInvalidInvite)
	}
	dataKey, err := dialLocatorKey(invite.Data.Host, invite.Data.Port)
	if err != nil {
		return fmt.Errorf("%w: data host: %v", ErrInvalidInvite, err)
	}
	enrollKey, err := dialLocatorKey(invite.Enrollment.Host, invite.Enrollment.Port)
	if err != nil {
		return fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	if dataKey == enrollKey {
		return fmt.Errorf("%w: data and enrollment locators must not share the same canonical host:port", ErrInvalidInvite)
	}
	if !isLowerHexDigest(invite.Enrollment.TLSSPKISHA256) {
		return fmt.Errorf("%w: enrollment tls_spki_sha256 must be a lowercase SHA-256 digest", ErrInvalidInvite)
	}
	if _, err := grant.DurationFromSeconds(invite.AuthorizationDurationSeconds); err != nil {
		return fmt.Errorf("%w: authorization_duration_seconds: %v", ErrInvalidInvite, err)
	}
	return nil
}

func canonicalizeStoredInvite(invite *Invite) error {
	if invite == nil {
		return fmt.Errorf("%w: invite is nil", ErrInvalidInvite)
	}
	dataHost, err := canonicalInviteHost(invite.Data.Host)
	if err != nil {
		return fmt.Errorf("%w: data host: %v", ErrInvalidInvite, err)
	}
	enrollHost, err := canonicalInviteHost(invite.Enrollment.Host)
	if err != nil {
		return fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	invite.Data.Host = dataHost
	invite.Enrollment.Host = enrollHost
	return validateInviteShape(*invite)
}

func canonicalInviteHost(value string) (string, error) {
	host, err := locator.ParseDialHost(value)
	if err != nil {
		return "", err
	}
	return host.Canonical()
}

func dialLocatorKey(host string, port uint16) (string, error) {
	canonical, err := canonicalInviteHost(host)
	if err != nil {
		return "", err
	}
	return canonical + "\x00" + fmt.Sprintf("%d", port), nil
}

func isLowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func recordPath(directory, inviteID string) string {
	return filepath.Join(directory, inviteID+".json")
}

func isSafeName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	contents, err := json.Marshal(value)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return writeFileAtomic(path, contents, mode)
}

func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".wt-invite-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err := temp.Write(contents); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
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
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
