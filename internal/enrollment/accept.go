package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/profile"
)

// DefaultEnrollmentPort is the fixed pinned-TLS enrollment listener port.
// SSH remains on the invite server_port; enrollment is a separate control path.
const DefaultEnrollmentPort uint16 = 29722

// DefaultManagementPort is the host-local rotate/revoke RPC port.
// It is reached through the authenticated tunnel, never as a public listener.
const DefaultManagementPort uint16 = 29723

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
	// InstallAuthorization must make the exact public key authorization
	// durable and is required for the production acceptance path. It must be
	// idempotent because Accept may call it again after an interrupted reply.
	// notAfter is the host-computed authorization expiry.
	InstallAuthorization func(publicKey string, notAfter time.Time) error
}

// AcceptResult is the durable, authorized enrollment outcome.
type AcceptResult struct {
	Proof     EnrollmentProof
	PublicKey string
	Invite    Invite
	ClientID  string
}

// Accept validates one enrollment request against a stored single-use invite,
// durably converges client state and authorization, consumes the invite, and
// returns a non-secret binding proof. An exact retry returns the same result;
// a conflicting reuse fails closed.
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
	publicKey := strings.TrimSpace(input.Request.PublicKey)
	clientID := clientIDFor(record.InviteID, publicKey)
	if record.Status == StatusConsumed {
		return resumeAcceptedEnrollment(input, record, clientID, publicKey)
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
	if input.InstallAuthorization == nil {
		return AcceptResult{}, errors.New("enrollment authorization installer is required")
	}

	if !now.Before(expires) {
		record.Status = StatusExpired
		_ = writeJSONAtomic(recordPath(input.Directory, record.InviteID), record, 0o600)
		return AcceptResult{}, fmt.Errorf("%w: invite expired", ErrInvalidInvite)
	}

	acceptedAt := now.Format(time.RFC3339Nano)
	authorizationSeconds := record.AuthorizationDurationSeconds
	if authorizationSeconds == 0 {
		return AcceptResult{}, fmt.Errorf("%w: invite missing authorization_duration_seconds", ErrInvalidInvite)
	}
	notAfter, notAfterEncoded, err := grant.AuthorizationNotAfter(now, authorizationSeconds)
	if err != nil {
		return AcceptResult{}, fmt.Errorf("%w: %v", ErrInvalidInvite, err)
	}
	serverAddress := firstNonEmpty(input.ServerAddress, record.ServerAddress)
	if input.ClientsDirectory != "" {
		wantClient := ClientRecord{
			ClientID:                     clientID,
			GrantID:                      grantIDFor(record.InviteID, publicKey),
			TunnelID:                     input.Request.TunnelID,
			RouteID:                      input.Request.TunnelID,
			InviteID:                     record.InviteID,
			PublicKey:                    publicKey,
			PublicKeySHA256:              PublicKeyDigest(publicKey),
			ManagementTokenSHA256:        HashManagementToken(input.Request.ManagementToken),
			Principal:                    record.Principal,
			ProfileID:                    record.ProfileID,
			ArtifactProfileID:            record.ArtifactProfileID,
			ServerAddress:                serverAddress,
			TargetAddress:                record.TargetAddress,
			TargetPort:                   record.TargetPort,
			Status:                       ClientStatusEnrollmentPending,
			AcceptedAt:                   acceptedAt,
			AuthorizationNotAfter:        notAfterEncoded,
			AuthorizationDurationSeconds: authorizationSeconds,
			Generation:                   now.Format("20060102T150405Z"),
		}
		client, err := storeOrResumePendingClient(input.ClientsDirectory, wantClient)
		if err != nil {
			return AcceptResult{}, err
		}
		acceptedAt = client.AcceptedAt
		notAfterEncoded = client.AuthorizationNotAfter
		authorizationSeconds = client.AuthorizationDurationSeconds
		storedNotAfter, parseErr := grant.ParseUTC(client.AuthorizationNotAfter)
		if parseErr != nil {
			return AcceptResult{}, fmt.Errorf("%w: stored authorization_not_after: %v", ErrInvalidInvite, parseErr)
		}
		notAfter = storedNotAfter
		if err := input.InstallAuthorization(publicKey, notAfter); err != nil {
			return AcceptResult{}, fmt.Errorf("install client authorization: %w", err)
		}
		if client.Status == ClientStatusEnrollmentPending {
			client.Status = ClientStatusActive
			if err := UpdateClient(input.ClientsDirectory, client); err != nil {
				return AcceptResult{}, err
			}
		}
	} else if err := input.InstallAuthorization(publicKey, notAfter); err != nil {
		return AcceptResult{}, fmt.Errorf("install client authorization: %w", err)
	}

	consumed, err := Consume(input.Directory, record.InviteID, clientID, now)
	if err != nil {
		return AcceptResult{}, err
	}

	enrollPort := consumed.EnrollPort
	if enrollPort == 0 {
		enrollPort = DefaultEnrollmentPort
	}
	proof := EnrollmentProof{
		InviteID:                     consumed.InviteID,
		ClientID:                     clientID,
		HostPublicKey:                consumed.HostPublicKey,
		PublicKey:                    publicKey,
		Target:                       fmt.Sprintf("%s:%d", consumed.TargetAddress, consumed.TargetPort),
		Principal:                    consumed.Principal,
		ProfileID:                    consumed.ProfileID,
		Nonce:                        consumed.Nonce,
		AcceptedAt:                   acceptedAt,
		AuthorizationNotAfter:        notAfterEncoded,
		AuthorizationDurationSeconds: authorizationSeconds,
		ServerAddress:                serverAddress,
		EnrollPort:                   enrollPort,
	}
	return AcceptResult{
		Proof:     proof,
		PublicKey: publicKey,
		Invite:    consumed.Invite,
		ClientID:  clientID,
	}, nil
}

func resumeAcceptedEnrollment(input AcceptInput, invite Record, clientID, publicKey string) (AcceptResult, error) {
	if invite.ClientID != clientID || input.ClientsDirectory == "" {
		return AcceptResult{}, fmt.Errorf("%w: invite has already been consumed", ErrInvalidInvite)
	}
	client, err := LoadClient(input.ClientsDirectory, clientID)
	if err != nil {
		return AcceptResult{}, fmt.Errorf("%w: consumed invite client state is unavailable", ErrInvalidInvite)
	}
	if client.Status != ClientStatusActive ||
		client.InviteID != invite.InviteID ||
		client.TunnelID != input.Request.TunnelID ||
		client.PublicKey != publicKey ||
		!constantTimeDigestEqual(client.ManagementTokenSHA256, HashManagementToken(input.Request.ManagementToken)) {
		return AcceptResult{}, fmt.Errorf("%w: invite retry does not match accepted enrollment", ErrInvalidInvite)
	}
	if input.InstallAuthorization == nil {
		return AcceptResult{}, errors.New("enrollment authorization installer is required")
	}
	notAfter, err := grant.ParseUTC(client.AuthorizationNotAfter)
	if err != nil {
		return AcceptResult{}, fmt.Errorf("%w: stored authorization_not_after: %v", ErrInvalidInvite, err)
	}
	if err := input.InstallAuthorization(publicKey, notAfter); err != nil {
		return AcceptResult{}, fmt.Errorf("reconcile client authorization: %w", err)
	}
	return acceptedResult(input, invite, client, publicKey), nil
}

func storeOrResumePendingClient(directory string, want ClientRecord) (ClientRecord, error) {
	err := StoreClient(directory, want)
	if err == nil {
		return want, nil
	}
	existing, loadErr := LoadClient(directory, want.ClientID)
	if loadErr != nil {
		return ClientRecord{}, err
	}
	if (existing.Status != ClientStatusEnrollmentPending && existing.Status != ClientStatusActive) ||
		existing.InviteID != want.InviteID ||
		existing.TunnelID != want.TunnelID ||
		existing.PublicKey != want.PublicKey ||
		!constantTimeDigestEqual(existing.ManagementTokenSHA256, want.ManagementTokenSHA256) ||
		existing.Principal != want.Principal ||
		existing.ProfileID != want.ProfileID ||
		existing.ServerAddress != want.ServerAddress ||
		existing.AuthorizationDurationSeconds != want.AuthorizationDurationSeconds ||
		existing.TargetAddress != want.TargetAddress ||
		existing.TargetPort != want.TargetPort {
		return ClientRecord{}, fmt.Errorf("%w: conflicting client enrollment state", ErrInvalidInvite)
	}
	return existing, nil
}

func acceptedResult(input AcceptInput, invite Record, client ClientRecord, publicKey string) AcceptResult {
	enrollPort := invite.EnrollPort
	if enrollPort == 0 {
		enrollPort = DefaultEnrollmentPort
	}
	proof := EnrollmentProof{
		InviteID:                     invite.InviteID,
		ClientID:                     client.ClientID,
		HostPublicKey:                invite.HostPublicKey,
		PublicKey:                    publicKey,
		Target:                       fmt.Sprintf("%s:%d", invite.TargetAddress, invite.TargetPort),
		Principal:                    invite.Principal,
		ProfileID:                    invite.ProfileID,
		Nonce:                        invite.Nonce,
		AcceptedAt:                   client.AcceptedAt,
		AuthorizationNotAfter:        client.AuthorizationNotAfter,
		AuthorizationDurationSeconds: client.AuthorizationDurationSeconds,
		ServerAddress:                firstNonEmpty(input.ServerAddress, invite.ServerAddress),
		EnrollPort:                   enrollPort,
	}
	return AcceptResult{Proof: proof, PublicKey: publicKey, Invite: invite.Invite, ClientID: client.ClientID}
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
	return fmt.Sprintf("https://%s/v1/enroll", joinHostPort(addr, port)), nil
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
	if !isManagementToken(request.ManagementToken) {
		return fmt.Errorf("%w: management_token must be 64 lowercase hex characters", ErrInvalidInvite)
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

func clientIDFor(inviteID, publicKey string) string {
	sum := sha256.Sum256([]byte(inviteID + "\x00" + strings.TrimSpace(publicKey)))
	return hex.EncodeToString(sum[:16])
}

func grantIDFor(inviteID, publicKey string) string {
	sum := sha256.Sum256([]byte(inviteID + "\x01" + strings.TrimSpace(publicKey)))
	return hex.EncodeToString(sum[:16])
}

func lockInvite(directory, inviteID string) (unlock func(), err error) {
	return lockPathExclusive(directory, "."+inviteID+".lock", "invite", false)
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
