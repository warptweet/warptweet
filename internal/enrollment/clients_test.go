package enrollment

import (
	"encoding/base64"
	"encoding/binary"
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
		ClientName:        "laptop-1",
		ServerAddress:     netip.MustParseAddr("192.0.2.10"),
		ServerPort:        2222,
		TargetAddress:     netip.MustParseAddr("198.51.100.20"),
		TargetPort:        5432,
		Principal:         "warptweet",
		ProfileID:         profile.CurrentID,
		ArtifactProfileID: "linux-amd64",
		HostPublicKey:     "ssh-mldsa44-ed25519@openssh.com AAAA host",
		Now:               now,
		Secret:            secret,
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
			InviteID:      invite.InviteID,
			Nonce:         invite.Nonce,
			ClientName:    invite.ClientName,
			PublicKey:     publicKey,
			ProfileID:     profile.CurrentID,
			TunnelID:      "laptop-1",
			ListenAddress: "127.0.0.1",
			ListenPort:    15432,
		},
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		ServerAddress: invite.ServerAddress,
		Now:           now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if result.Proof.ManagementToken == "" {
		t.Fatal("missing management token")
	}
	loaded, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if loaded.Status != ClientStatusActive || loaded.ManagementTokenSHA256 == result.Proof.ManagementToken {
		t.Fatalf("client record insecure or wrong: %+v", loaded)
	}

	revoked, err := RevokeClient(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: result.Proof.ManagementToken,
		TunnelID:        "laptop-1",
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	if revoked.Status != ClientStatusRevoked {
		t.Fatalf("status=%s", revoked.Status)
	}
	again, err := RevokeClient(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: result.Proof.ManagementToken,
		TunnelID:        "laptop-1",
	}, now.Add(3*time.Minute))
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
		ClientName:        "studio-mac",
		ServerAddress:     netip.MustParseAddr("192.0.2.10"),
		ServerPort:        2222,
		TargetAddress:     netip.MustParseAddr("198.51.100.20"),
		TargetPort:        5432,
		Principal:         "warptweet",
		ProfileID:         profile.CurrentID,
		ArtifactProfileID: "linux-amd64",
		HostPublicKey:     "ssh-mldsa44-ed25519@openssh.com AAAA host",
		Now:               now,
		Secret:            secret,
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
			InviteID:      invite.InviteID,
			Nonce:         invite.Nonce,
			ClientName:    invite.ClientName,
			PublicKey:     firstKey,
			ProfileID:     profile.CurrentID,
			TunnelID:      "studio-mac",
			ListenAddress: "127.0.0.1",
			ListenPort:    15432,
		},
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Now:           now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	// Distinct key material for rotate.
	secondKey := testCompositePublicKeyRotated()
	updated, token, err := RotateClientPublicKey(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: result.Proof.ManagementToken,
		TunnelID:        "studio-mac",
	}, secondKey, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("RotateClientPublicKey: %v", err)
	}
	if token == "" || token == result.Proof.ManagementToken {
		t.Fatalf("token not rotated")
	}
	if updated.PublicKey != secondKey {
		t.Fatalf("public key not updated")
	}
	if _, _, err := RotateClientPublicKey(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: result.Proof.ManagementToken,
		TunnelID:        "studio-mac",
	}, firstKey, now.Add(3*time.Minute)); err == nil {
		t.Fatal("old management token still accepted")
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
