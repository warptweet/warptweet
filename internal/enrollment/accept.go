package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/profile"
)

// DefaultEnrollmentPort is the fixed HTTP enrollment listener port.
// SSH remains on the invite server_port; enrollment is a separate control path.
const DefaultEnrollmentPort uint16 = 29722

// MaxEnrollmentRequestBytes bounds enrollment request JSON on the wire.
const MaxEnrollmentRequestBytes = 16 << 10

// AcceptInput is the server-side enrollment acceptance request.
type AcceptInput struct {
	Directory        string
	ClientsDirectory string
	Request          EnrollmentRequest
	HostPublicKey    string
	Principal        string
	ProfileID        string
	TargetAddress    string
	TargetPort       uint16
	ServerAddress    string
	Now              time.Time
}

// AcceptResult is the durable accept outcome before authorized_keys install.
type AcceptResult struct {
	Proof     EnrollmentProof
	PublicKey string
	Invite    Invite
	ClientID  string
}

// Accept validates one enrollment request against a stored single-use invite,
// consumes the invite, and returns the binding proof. Callers install
// authorized_keys from Proof.PublicKey after Accept succeeds.
//
// Order is validate → exclusive lock → re-check → consume → proof. A failed
// authorized_keys write after Accept leaves the invite consumed (fail closed;
// mint a new invite).
func Accept(input AcceptInput) (AcceptResult, error) {
	if input.Directory == "" {
		return AcceptResult{}, fmt.Errorf("%w: invite directory is required", ErrInvalidInvite)
	}
	if err := validateEnrollmentRequest(input.Request); err != nil {
		return AcceptResult{}, err
	}
	if strings.TrimSpace(input.HostPublicKey) == "" || strings.ContainsAny(input.HostPublicKey, "\r\n\x00") {
		return AcceptResult{}, fmt.Errorf("%w: host public key is required", ErrInvalidInvite)
	}
	if input.Principal == "" || input.ProfileID == "" {
		return AcceptResult{}, fmt.Errorf("%w: principal and profile_id are required", ErrInvalidInvite)
	}
	if input.ProfileID != profile.CurrentID || input.Request.ProfileID != profile.CurrentID {
		return AcceptResult{}, fmt.Errorf("%w: unsupported profile_id", ErrInvalidInvite)
	}
	if input.TargetAddress == "" || input.TargetPort == 0 {
		return AcceptResult{}, fmt.Errorf("%w: target is required", ErrInvalidInvite)
	}

	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	unlock, err := lockInvite(input.Directory, input.Request.InviteID)
	if err != nil {
		return AcceptResult{}, err
	}
	defer unlock()

	record, err := Load(input.Directory, input.Request.InviteID)
	if err != nil {
		return AcceptResult{}, fmt.Errorf("%w: unknown invite", ErrInvalidInvite)
	}
	if record.Status != StatusIssued {
		return AcceptResult{}, fmt.Errorf("%w: invite status is %q", ErrInvalidInvite, record.Status)
	}
	if record.Nonce != input.Request.Nonce {
		return AcceptResult{}, fmt.Errorf("%w: invite nonce mismatch", ErrInvalidInvite)
	}
	if record.ClientName != input.Request.ClientName {
		return AcceptResult{}, fmt.Errorf("%w: client_name mismatch", ErrInvalidInvite)
	}
	if record.ProfileID != input.Request.ProfileID || record.ProfileID != input.ProfileID {
		return AcceptResult{}, fmt.Errorf("%w: profile_id mismatch", ErrInvalidInvite)
	}
	if record.Principal != input.Principal {
		return AcceptResult{}, fmt.Errorf("%w: principal mismatch", ErrInvalidInvite)
	}
	if record.TargetAddress != input.TargetAddress || record.TargetPort != input.TargetPort {
		return AcceptResult{}, fmt.Errorf("%w: target mismatch", ErrInvalidInvite)
	}
	if record.HostPublicKey != strings.TrimSpace(input.HostPublicKey) {
		return AcceptResult{}, fmt.Errorf("%w: host public key mismatch", ErrInvalidInvite)
	}

	expires, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil {
		expires, err = time.Parse(time.RFC3339, record.ExpiresAt)
		if err != nil {
			return AcceptResult{}, fmt.Errorf("%w: parse expires_at", ErrInvalidInvite)
		}
	}
	if !now.Before(expires) {
		record.Status = StatusExpired
		_ = writeJSONAtomic(recordPath(input.Directory, record.InviteID), record, 0o600)
		return AcceptResult{}, fmt.Errorf("%w: invite expired", ErrInvalidInvite)
	}

	publicKey := strings.TrimSpace(input.Request.PublicKey)
	clientID, err := newClientID(publicKey)
	if err != nil {
		return AcceptResult{}, err
	}

	consumed, err := Consume(input.Directory, record.InviteID, clientID, now)
	if err != nil {
		return AcceptResult{}, err
	}

	acceptedAt := now.Format(time.RFC3339Nano)
	token := ""
	if input.ClientsDirectory != "" {
		generated, err := GenerateManagementToken()
		if err != nil {
			return AcceptResult{}, err
		}
		token = generated
		serverAddress := input.ServerAddress
		if serverAddress == "" {
			serverAddress = consumed.ServerAddress
		}
		if err := StoreClient(input.ClientsDirectory, ClientRecord{
			ClientID:              clientID,
			TunnelID:              input.Request.TunnelID,
			InviteID:              consumed.InviteID,
			PublicKey:             publicKey,
			PublicKeySHA256:       PublicKeyDigest(publicKey),
			ManagementTokenSHA256: HashManagementToken(token),
			Principal:             consumed.Principal,
			ProfileID:             consumed.ProfileID,
			ServerAddress:         serverAddress,
			Status:                ClientStatusActive,
			AcceptedAt:            acceptedAt,
			Generation:            now.Format("20060102T150405Z"),
		}); err != nil {
			return AcceptResult{}, err
		}
	}

	enrollPort := consumed.EnrollPort
	if enrollPort == 0 {
		enrollPort = DefaultEnrollmentPort
	}
	proof := EnrollmentProof{
		InviteID:        consumed.InviteID,
		ClientID:        clientID,
		HostPublicKey:   consumed.HostPublicKey,
		PublicKey:       publicKey,
		Target:          fmt.Sprintf("%s:%d", consumed.TargetAddress, consumed.TargetPort),
		Principal:       consumed.Principal,
		ProfileID:       consumed.ProfileID,
		Nonce:           consumed.Nonce,
		AcceptedAt:      acceptedAt,
		ManagementToken: token,
		ServerAddress:   firstNonEmpty(input.ServerAddress, consumed.ServerAddress),
		EnrollPort:      enrollPort,
	}
	return AcceptResult{
		Proof:     proof,
		PublicKey: publicKey,
		Invite:    consumed.Invite,
		ClientID:  clientID,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// EnrollmentURL builds the client enrollment URL for a server address.
func EnrollmentURL(serverAddress string, port uint16) (string, error) {
	if port == 0 {
		port = DefaultEnrollmentPort
	}
	addr, err := parseHostForURL(serverAddress)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s/v1/enroll", joinHostPort(addr, port)), nil
}

func validateEnrollmentRequest(request EnrollmentRequest) error {
	if request.InviteID == "" || request.Nonce == "" || request.ClientName == "" {
		return fmt.Errorf("%w: invite_id, nonce, and client_name are required", ErrInvalidInvite)
	}
	if !isHexID(request.InviteID) {
		return fmt.Errorf("%w: invite_id must be hex", ErrInvalidInvite)
	}
	if !isHexID(request.Nonce) {
		return fmt.Errorf("%w: nonce must be hex", ErrInvalidInvite)
	}
	if !isSafeName(request.ClientName) {
		return fmt.Errorf("%w: client_name is invalid", ErrInvalidInvite)
	}
	if request.ProfileID == "" || request.TunnelID == "" {
		return fmt.Errorf("%w: profile_id and tunnel_id are required", ErrInvalidInvite)
	}
	if request.ListenAddress != "127.0.0.1" {
		return fmt.Errorf("%w: listen_address must be 127.0.0.1", ErrInvalidInvite)
	}
	if request.ListenPort == 0 {
		return fmt.Errorf("%w: listen_port must be nonzero", ErrInvalidInvite)
	}
	return validatePublicKeyLine(request.PublicKey)
}

func validatePublicKeyLine(publicKey string) error {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" || strings.ContainsAny(publicKey, "\r\n\x00") {
		return fmt.Errorf("%w: public_key must be one line", ErrInvalidInvite)
	}
	if len(publicKey) > MaxEnrollmentRequestBytes {
		return fmt.Errorf("%w: public_key is too large", ErrInvalidInvite)
	}
	fields := strings.Fields(publicKey)
	if len(fields) < 2 {
		return fmt.Errorf("%w: public_key must contain type and blob", ErrInvalidInvite)
	}
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInvite, err)
	}
	if fields[0] != selected.AuthenticationKeyType {
		return fmt.Errorf("%w: public_key type is not the required composite algorithm", ErrInvalidInvite)
	}
	lower := strings.ToLower(publicKey)
	for _, forbidden := range []string{"private", "begin openssh", "begin rsa", "begin ec", "seed"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("%w: public_key must not contain private-key material", ErrInvalidInvite)
		}
	}
	return nil
}

func newClientID(publicKey string) (string, error) {
	sum := sha256.Sum256([]byte(publicKey))
	// Mix in random bits so two enroll attempts with the same key do not collide
	// on client_id if a prior attempt was revoked out-of-band.
	extra := make([]byte, 8)
	if _, err := rand.Read(extra); err != nil {
		return "", fmt.Errorf("generate client id: %w", err)
	}
	mixed := sha256.Sum256(append(sum[:], extra...))
	return hex.EncodeToString(mixed[:16]), nil
}

func lockInvite(directory, inviteID string) (unlock func(), err error) {
	return lockPathExclusive(directory, "."+inviteID+".lock", "invite")
}

func isHexID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func parseHostForURL(serverAddress string) (string, error) {
	value := strings.TrimSpace(serverAddress)
	if value == "" {
		return "", fmt.Errorf("%w: server address is required", ErrInvalidInvite)
	}
	return value, nil
}

func joinHostPort(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
