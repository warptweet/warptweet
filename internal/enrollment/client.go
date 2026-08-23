package enrollment

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/profile"
)

// ClientView is the non-secret invite summary shown before enrollment.
type ClientView struct {
	InviteID                     string `json:"invite_id"`
	ClientName                   string `json:"client_name"`
	ServerAddress                string `json:"server_address"`
	ServerPort                   uint16 `json:"server_port"`
	TargetAddress                string `json:"target_address"`
	TargetPort                   uint16 `json:"target_port"`
	Principal                    string `json:"principal"`
	ProfileID                    string `json:"profile_id"`
	ArtifactProfileID            string `json:"artifact_profile_id"`
	HostPublicKey                string `json:"host_public_key"`
	EnrollmentTLSSPKISHA256      string `json:"enrollment_tls_spki_sha256"`
	ExpiresAt                    string `json:"expires_at"`
	AuthorizationDurationSeconds int64  `json:"authorization_duration_seconds"`
	ListenAddress                string `json:"listen_address"`
	ListenPort                   uint16 `json:"listen_port"`
	TunnelID                     string `json:"tunnel_id"`
}

// ParseClientInvite validates invite JSON shape before any network activity.
// An invite is a confidential bearer. The host durable record is the grant authority.
func ParseClientInvite(raw []byte, now time.Time) (Invite, ClientView, error) {
	if len(raw) == 0 {
		return Invite{}, ClientView{}, fmt.Errorf("%w: input is empty", ErrInvalidInvite)
	}
	if len(raw) > MaxInviteBytes {
		return Invite{}, ClientView{}, fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidInvite, MaxInviteBytes)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"private", "begin openssh", "begin rsa", "begin ec", "seed"} {
		if strings.Contains(lower, forbidden) {
			return Invite{}, ClientView{}, fmt.Errorf("%w: invite must not contain private-key material", ErrInvalidInvite)
		}
	}
	var invite Invite
	if err := decodeStrictJSON(raw, &invite); err != nil {
		return Invite{}, ClientView{}, fmt.Errorf("%w: %v", ErrInvalidInvite, err)
	}
	if err := validateInviteShape(invite); err != nil {
		return Invite{}, ClientView{}, err
	}
	if invite.ProfileID != profile.CurrentID {
		return Invite{}, ClientView{}, fmt.Errorf("%w: unsupported profile_id", ErrInvalidInvite)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expires, err := time.Parse(time.RFC3339Nano, invite.ExpiresAt)
	if err != nil {
		// allow RFC3339 without nano
		expires, err = time.Parse(time.RFC3339, invite.ExpiresAt)
		if err != nil {
			return Invite{}, ClientView{}, fmt.Errorf("%w: parse expires_at: %v", ErrInvalidInvite, err)
		}
	}
	if !now.Before(expires) {
		return Invite{}, ClientView{}, fmt.Errorf("%w: invite expired", ErrInvalidInvite)
	}
	tunnelID := sanitizeTunnelID(invite.ClientName)
	// Legacy transfer documents may omit enroll_port; fill the product default.
	if invite.EnrollPort == 0 {
		invite.EnrollPort = DefaultEnrollmentPort
	}
	view := ClientView{
		InviteID:                     invite.InviteID,
		ClientName:                   invite.ClientName,
		ServerAddress:                invite.ServerAddress,
		ServerPort:                   invite.ServerPort,
		TargetAddress:                invite.TargetAddress,
		TargetPort:                   invite.TargetPort,
		Principal:                    invite.Principal,
		ProfileID:                    invite.ProfileID,
		ArtifactProfileID:            invite.ArtifactProfileID,
		HostPublicKey:                invite.HostPublicKey,
		EnrollmentTLSSPKISHA256:      invite.EnrollmentTLSSPKISHA256,
		ExpiresAt:                    invite.ExpiresAt,
		AuthorizationDurationSeconds: invite.AuthorizationDurationSeconds,
		ListenAddress:                "127.0.0.1",
		ListenPort:                   15432,
		TunnelID:                     tunnelID,
	}
	return invite, view, nil
}

// EnrollmentPort returns the HTTP enrollment control port from an invite.
func (invite Invite) EnrollmentPort() uint16 {
	if invite.EnrollPort == 0 {
		return DefaultEnrollmentPort
	}
	return invite.EnrollPort
}

// BuildClientManifest renders a client .wt document from one invite and digest.
func BuildClientManifest(invite Invite, tunnelID string, listenPort uint16, sshDigest string) (config.Config, error) {
	serverAddr, err := netip.ParseAddr(invite.ServerAddress)
	if err != nil {
		return config.Config{}, err
	}
	targetAddr, err := netip.ParseAddr(invite.TargetAddress)
	if err != nil {
		return config.Config{}, err
	}
	if listenPort == 0 {
		listenPort = 15432
	}
	if tunnelID == "" {
		tunnelID = sanitizeTunnelID(invite.ClientName)
	}
	manifest := config.Config{
		Kind:            config.ClientTunnelsKind,
		SchemaVersion:   config.CurrentSchemaVersion,
		ProfileID:       invite.ProfileID,
		SSHBinarySHA256: sshDigest,
		Server: config.Server{
			Address: serverAddr,
			Port:    config.Port(invite.ServerPort),
			User:    invite.Principal,
		},
		Tunnels: []config.Tunnel{{
			ID: tunnelID,
			Listen: config.Endpoint{
				Address: netip.MustParseAddr("127.0.0.1"),
				Port:    config.Port(listenPort),
			},
			Target: config.Endpoint{
				Address: targetAddr,
				Port:    config.Port(invite.TargetPort),
			},
		}},
		Supervision: config.Supervision{
			InitialBackoff: config.Duration(time.Second),
			MaxBackoff:     config.Duration(30 * time.Second),
		},
	}
	if err := config.Validate(manifest); err != nil {
		return config.Config{}, err
	}
	return manifest, nil
}

// EnrollmentRequest is the bounded payload submitted to the WarpTweet host.
type EnrollmentRequest struct {
	InviteID        string `json:"invite_id"`
	Nonce           string `json:"nonce"`
	ClientName      string `json:"client_name"`
	PublicKey       string `json:"public_key"`
	ProfileID       string `json:"profile_id"`
	TunnelID        string `json:"tunnel_id"`
	ListenAddress   string `json:"listen_address"`
	ListenPort      uint16 `json:"listen_port"`
	ManagementToken string `json:"management_token"`
}

// EnrollmentProof is the non-secret server binding returned after accept.
// The management capability is generated and retained by the client; the
// server never returns or stores its raw value.
type EnrollmentProof struct {
	InviteID                     string `json:"invite_id"`
	ClientID                     string `json:"client_id"`
	HostPublicKey                string `json:"host_public_key"`
	PublicKey                    string `json:"public_key"`
	Target                       string `json:"target"`
	Principal                    string `json:"principal"`
	ProfileID                    string `json:"profile_id"`
	Nonce                        string `json:"nonce"`
	AcceptedAt                   string `json:"accepted_at"`
	AuthorizationNotAfter        string `json:"authorization_not_after"`
	AuthorizationDurationSeconds int64  `json:"authorization_duration_seconds"`
	ServerAddress                string `json:"server_address,omitempty"`
	EnrollPort                   uint16 `json:"enroll_port,omitempty"`
}

// EncodeEnrollmentRequest returns canonical request JSON.
func EncodeEnrollmentRequest(request EnrollmentRequest) ([]byte, error) {
	return json.Marshal(request)
}

// ValidateEnrollmentProof checks the server proof binds the expected facts.
func ValidateEnrollmentProof(proof EnrollmentProof, invite Invite, publicKey string) error {
	if proof.InviteID != invite.InviteID ||
		proof.Nonce != invite.Nonce ||
		proof.ProfileID != invite.ProfileID ||
		proof.Principal != invite.Principal ||
		proof.HostPublicKey != invite.HostPublicKey ||
		proof.PublicKey != publicKey {
		return fmt.Errorf("%w: enrollment proof does not bind invite and client key", ErrInvalidInvite)
	}
	wantTarget := fmt.Sprintf("%s:%d", invite.TargetAddress, invite.TargetPort)
	if proof.Target != wantTarget {
		return fmt.Errorf("%w: enrollment proof target mismatch", ErrInvalidInvite)
	}
	if proof.ClientID == "" {
		return fmt.Errorf("%w: enrollment proof missing client_id", ErrInvalidInvite)
	}
	if proof.AuthorizationDurationSeconds != invite.AuthorizationDurationSeconds {
		return fmt.Errorf("%w: enrollment proof authorization duration mismatch", ErrInvalidInvite)
	}
	acceptedAt, err := grant.ParseUTC(proof.AcceptedAt)
	if err != nil {
		return fmt.Errorf("%w: enrollment proof accepted_at: %v", ErrInvalidInvite, err)
	}
	_, wantNotAfter, err := grant.AuthorizationNotAfter(acceptedAt, proof.AuthorizationDurationSeconds)
	if err != nil {
		return fmt.Errorf("%w: enrollment proof authorization_not_after: %v", ErrInvalidInvite, err)
	}
	gotNotAfter, err := grant.ParseUTC(proof.AuthorizationNotAfter)
	if err != nil {
		return fmt.Errorf("%w: enrollment proof authorization_not_after: %v", ErrInvalidInvite, err)
	}
	wantParsed, err := grant.ParseUTC(wantNotAfter)
	if err != nil || !gotNotAfter.Equal(wantParsed) {
		return fmt.Errorf("%w: enrollment proof authorization_not_after mismatch", ErrInvalidInvite)
	}
	return nil
}

func sanitizeTunnelID(name string) string {
	// Reuse invite label rules so tunnel ids match client_name basenames and
	// satisfy the lowercase tunnel_id contract in client manifests.
	return SanitizeInviteLabel(name)
}
