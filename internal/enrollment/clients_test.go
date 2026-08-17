package enrollment

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/profile"
)

func TestAcceptStoresClientAndRevokeBurnsToken(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 14, 20, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:              "laptop-1",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               profile.CurrentID,
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		Now:                     now,
		Secret:                  secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	publicKey := testCompositePublicKey()
	result, err := Accept(AcceptInput{
		Directory:        invites,
		ClientsDirectory: clients,
		Request: EnrollmentRequest{
			InviteID:        invite.InviteID,
			Nonce:           invite.Nonce,
			ClientName:      invite.ClientName,
			PublicKey:       publicKey,
			ProfileID:       profile.CurrentID,
			TunnelID:        "laptop-1",
			ListenAddress:   "127.0.0.1",
			ListenPort:      15432,
			ManagementToken: testManagementToken,
		},
		HostPublicKey:        invite.HostPublicKey,
		Principal:            invite.Principal,
		ProfileID:            profile.CurrentID,
		TargetAddress:        invite.TargetAddress,
		TargetPort:           invite.TargetPort,
		ServerAddress:        invite.ServerAddress,
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	loaded, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if loaded.Status != ClientStatusActive || loaded.ManagementTokenSHA256 != HashManagementToken(testManagementToken) {
		t.Fatalf("client record insecure or wrong: %+v", loaded)
	}

	revokeRequest := ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: testManagementToken,
		TunnelID:        "laptop-1",
	}
	if _, err := RevokeClient(clients, revokeRequest, now.Add(2*time.Minute), func(string) error {
		return errors.New("injected authorization removal failure")
	}, nil, nil); err == nil {
		t.Fatal("RevokeClient succeeded despite injected authorization failure")
	}
	pendingRevoke, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatalf("LoadClient pending revoke: %v", err)
	}
	if pendingRevoke.Status != ClientStatusRevocationPending {
		t.Fatalf("status=%s, want revocation_pending", pendingRevoke.Status)
	}
	revoked, err := RevokeClient(clients, revokeRequest, now.Add(2*time.Minute), func(string) error { return nil }, nil, nil)
	if err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	if revoked.Status != ClientStatusRevoked {
		t.Fatalf("status=%s", revoked.Status)
	}
	again, err := RevokeClient(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: testManagementToken,
		TunnelID:        "laptop-1",
	}, now.Add(3*time.Minute), func(string) error { return nil }, nil, nil)
	if err != nil {
		t.Fatalf("second RevokeClient should be idempotent: %v", err)
	}
	if again.Status != ClientStatusRevoked || again.ClientID != result.ClientID {
		t.Fatalf("second revoke record=%+v", again)
	}
}

func TestRotateClientIssuesNewToken(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 14, 21, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:              "studio-mac",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               profile.CurrentID,
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		Now:                     now,
		Secret:                  secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	firstKey := testCompositePublicKey()
	result, err := Accept(AcceptInput{
		Directory:        invites,
		ClientsDirectory: clients,
		Request: EnrollmentRequest{
			InviteID:        invite.InviteID,
			Nonce:           invite.Nonce,
			ClientName:      invite.ClientName,
			PublicKey:       firstKey,
			ProfileID:       profile.CurrentID,
			TunnelID:        "studio-mac",
			ListenAddress:   "127.0.0.1",
			ListenPort:      15432,
			ManagementToken: testManagementToken,
		},
		HostPublicKey:        invite.HostPublicKey,
		Principal:            invite.Principal,
		ProfileID:            profile.CurrentID,
		TargetAddress:        invite.TargetAddress,
		TargetPort:           invite.TargetPort,
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	// Distinct key material for rotate.
	secondKey := testCompositePublicKeyRotated()
	rotateRequest := ManagementRequest{
		ClientID:            result.ClientID,
		ManagementToken:     testManagementToken,
		TunnelID:            "studio-mac",
		NextManagementToken: testNextManagementToken,
	}
	if _, err := RotateClientPublicKey(clients, rotateRequest, secondKey, now.Add(2*time.Minute), func(string, string) error {
		return errors.New("injected authorization replacement failure")
	}); err == nil {
		t.Fatal("RotateClientPublicKey succeeded despite injected authorization failure")
	}
	pendingRotation, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatalf("LoadClient pending rotation: %v", err)
	}
	if pendingRotation.Status != ClientStatusRotationPending || pendingRotation.PendingPublicKey != secondKey {
		t.Fatalf("pending rotation=%+v", pendingRotation)
	}
	updated, err := RotateClientPublicKey(clients, rotateRequest, secondKey, now.Add(2*time.Minute), func(string, string) error { return nil })
	if err != nil {
		t.Fatalf("RotateClientPublicKey: %v", err)
	}
	if updated.ManagementTokenSHA256 != HashManagementToken(testNextManagementToken) {
		t.Fatalf("token hash not rotated")
	}
	if updated.PublicKey != secondKey {
		t.Fatalf("public key not updated")
	}
	if _, err := RotateClientPublicKey(
		clients,
		rotateRequest,
		secondKey,
		now.Add(3*time.Minute),
		func(string, string) error { return nil },
	); err != nil {
		t.Fatalf("exact response-loss rotation retry: %v", err)
	}
	if _, err := RotateClientPublicKey(clients, ManagementRequest{
		ClientID:            result.ClientID,
		ManagementToken:     testManagementToken,
		TunnelID:            "studio-mac",
		NextManagementToken: testNextManagementToken,
	}, firstKey, now.Add(4*time.Minute), func(string, string) error { return nil }); err == nil {
		t.Fatal("old management token still accepted")
	}
}

func TestRotateClientRejectsHostExpiredGrant(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 14, 21, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                   "studio-mac",
		ServerAddress:                netip.MustParseAddr("192.0.2.10"),
		ServerPort:                   2222,
		TargetAddress:                netip.MustParseAddr("198.51.100.20"),
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    profile.CurrentID,
		ArtifactProfileID:            "linux-amd64",
		HostPublicKey:                "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:      testEnrollmentTLSSPKIPin,
		AuthorizationDurationSeconds: 3600,
		Now:                          now,
		Secret:                       secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	result, err := Accept(AcceptInput{
		Directory:        invites,
		ClientsDirectory: clients,
		Request: EnrollmentRequest{
			InviteID:        invite.InviteID,
			Nonce:           invite.Nonce,
			ClientName:      invite.ClientName,
			PublicKey:       testCompositePublicKey(),
			ProfileID:       profile.CurrentID,
			TunnelID:        "studio-mac",
			ListenAddress:   "127.0.0.1",
			ListenPort:      15432,
			ManagementToken: testManagementToken,
		},
		HostPublicKey:        invite.HostPublicKey,
		Principal:            invite.Principal,
		ProfileID:            profile.CurrentID,
		TargetAddress:        invite.TargetAddress,
		TargetPort:           invite.TargetPort,
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := RotateClientPublicKey(clients, ManagementRequest{
		ClientID:            result.ClientID,
		ManagementToken:     testManagementToken,
		TunnelID:            "studio-mac",
		NextManagementToken: testNextManagementToken,
	}, testCompositePublicKeyRotated(), now.Add(2*time.Hour), func(string, string) error {
		t.Fatal("replaced authorization after host expiry")
		return nil
	}); err == nil {
		t.Fatal("RotateClientPublicKey accepted a host-expired grant")
	}
}

func testCompositePublicKeyRotated() string {
	algorithm := "ssh-mldsa44-ed25519@openssh.com"
	rawSize := 1344
	name := []byte(algorithm)
	blob := make([]byte, 4+len(name)+4+rawSize)
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(rawSize))
	for index := 0; index < rawSize; index++ {
		blob[offset+4+index] = byte(255 - index)
	}
	return algorithm + " " + base64.StdEncoding.EncodeToString(blob)
}
