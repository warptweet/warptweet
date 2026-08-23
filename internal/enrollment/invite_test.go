package enrollment

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateParseConsumeInviteLifecycle(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:              "laptop-1",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               "profile-v1",
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		TTL:                     DefaultTTL,
		Now:                     now,
		Secret:                  secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if record.Status != StatusIssued || invite.MAC == "" || invite.InviteID == "" {
		t.Fatalf("unexpected invite: %+v record=%+v", invite, record)
	}

	raw, err := Encode(invite)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(raw), "BEGIN") || strings.Contains(strings.ToLower(string(raw)), "private") {
		t.Fatal("invite encoding contains private-key markers")
	}

	parsed, err := ParseAndVerify(raw, secret, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ParseAndVerify: %v", err)
	}
	if parsed.InviteID != invite.InviteID {
		t.Fatalf("parsed id = %q", parsed.InviteID)
	}
	if _, err := ParseAndVerify(raw, secret, now.Add(DefaultTTL+time.Second)); err == nil {
		t.Fatal("ParseAndVerify accepted expired invite")
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := ParseAndVerify(tampered, secret, now.Add(time.Minute)); err == nil {
		t.Fatal("ParseAndVerify accepted tampered invite")
	}

	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	consumed, err := Consume(directory, invite.InviteID, "client-1", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.Status != StatusConsumed || consumed.ClientID != "client-1" {
		t.Fatalf("unexpected consumed record: %+v", consumed)
	}
	if _, err := Consume(directory, invite.InviteID, "client-2", now.Add(3*time.Minute)); err == nil {
		t.Fatal("Consume allowed invite reuse")
	}
}

func TestRevokeInvite(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 12, 13, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:              "laptop-2",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               "profile-v1",
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		Now:                     now,
		Secret:                  secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	directory := filepath.Join(t.TempDir(), "invites")
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	cancelled, err := Cancel(directory, invite.InviteID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.Status != StatusCancelled {
		t.Fatalf("status = %q", cancelled.Status)
	}
	if _, err := Consume(directory, invite.InviteID, "client", now.Add(2*time.Minute)); err == nil {
		t.Fatal("Consume accepted cancelled invite")
	}
	if _, err := Revoke(directory, invite.InviteID, now.Add(3*time.Minute)); err == nil {
		t.Fatal("Revoke accepted an unconsumed invite")
	}
}

func TestRevokeConsumedInvite(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 13, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:              "laptop-3",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               "profile-v1",
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		Now:                     now,
		Secret:                  secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	if _, err := Consume(directory, invite.InviteID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now.Add(time.Minute)); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	revoked, err := Revoke(directory, invite.InviteID, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked {
		t.Fatalf("status=%s", revoked.Status)
	}
	again, err := Revoke(directory, invite.InviteID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != StatusRevoked {
		t.Fatalf("idempotent status=%s", again.Status)
	}
}

func TestCancelExpiredUnconsumedInvite(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 20, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:              "expired-invite",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               "profile-v1",
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		Now:                     now,
		Secret:                  secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	if _, err := Consume(directory, invite.InviteID, "client", now.Add(48*time.Hour)); err == nil {
		t.Fatal("Consume accepted an expired invite")
	}
	loaded, err := Load(directory, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != StatusExpired || loaded.ClientID != "" {
		t.Fatalf("expired invite=%+v", loaded)
	}
	cancelled, err := Cancel(directory, invite.InviteID, now.Add(49*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != StatusCancelled {
		t.Fatalf("status=%s", cancelled.Status)
	}
}

func TestCreateBindsAuthorizationDurationToMAC(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	invite, _, err := Create(CreateInput{
		ClientName:                   "laptop-1",
		ServerAddress:                netip.MustParseAddr("192.0.2.10"),
		ServerPort:                   2222,
		TargetAddress:                netip.MustParseAddr("198.51.100.20"),
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    "profile-v1",
		ArtifactProfileID:            "linux-amd64",
		HostPublicKey:                "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:      testEnrollmentTLSSPKIPin,
		TTL:                          DefaultTTL,
		AuthorizationDurationSeconds: 3600,
		Now:                          now,
		Secret:                       secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if invite.SchemaVersion != 2 || invite.AuthorizationDurationSeconds != 3600 {
		t.Fatalf("invite=%+v", invite)
	}
	raw, err := Encode(invite)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := ParseAndVerify(raw, secret, now.Add(time.Minute)); err != nil {
		t.Fatalf("ParseAndVerify: %v", err)
	}
	tampered := []byte(strings.Replace(string(raw), `"authorization_duration_seconds":3600`, `"authorization_duration_seconds":7200`, 1))
	if _, err := ParseAndVerify(tampered, secret, now.Add(time.Minute)); err == nil {
		t.Fatal("ParseAndVerify accepted a duration that was not in the original MAC binding")
	}
}

func TestCreateRejectsDurationAboveMaximum(t *testing.T) {
	t.Parallel()

	secret := make([]byte, InviteSecretBytes)
	_, _, err := Create(CreateInput{
		ClientName:                          "laptop-1",
		ServerAddress:                       netip.MustParseAddr("192.0.2.10"),
		ServerPort:                          2222,
		TargetAddress:                       netip.MustParseAddr("198.51.100.20"),
		TargetPort:                          5432,
		Principal:                           "warptweet",
		ProfileID:                           "profile",
		ArtifactProfileID:                   "linux-amd64",
		HostPublicKey:                       "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:             testEnrollmentTLSSPKIPin,
		AuthorizationDurationSeconds:        31536001,
		MaximumAuthorizationDurationSeconds: 31536000,
		Secret:                              secret,
	})
	if err == nil {
		t.Fatal("Create accepted a duration above the host maximum")
	}
}

func TestCreateRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	secret := make([]byte, InviteSecretBytes)
	_, _, err := Create(CreateInput{
		ClientName:              "../evil",
		ServerAddress:           netip.MustParseAddr("192.0.2.10"),
		ServerPort:              2222,
		TargetAddress:           netip.MustParseAddr("198.51.100.20"),
		TargetPort:              5432,
		Principal:               "warptweet",
		ProfileID:               "profile",
		ArtifactProfileID:       "linux-amd64",
		HostPublicKey:           "key",
		EnrollmentTLSSPKISHA256: testEnrollmentTLSSPKIPin,
		Secret:                  secret,
	})
	if err == nil {
		t.Fatal("Create accepted unsafe client name")
	}
}

func TestInviteIDRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	invite := Invite{
		Kind:                         KindInvite,
		SchemaVersion:                CurrentSchemaVersion,
		InviteID:                     "../../../tmp",
		ClientName:                   "laptop-1",
		ServerAddress:                "192.0.2.10",
		ServerPort:                   2222,
		EnrollPort:                   29722,
		TargetAddress:                "198.51.100.20",
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    "profile-v1",
		Nonce:                        strings.Repeat("ab", 16),
		MAC:                          strings.Repeat("cd", 32),
		EnrollmentTLSSPKISHA256:      strings.Repeat("ab", 32),
		AuthorizationDurationSeconds: 2592000,
	}
	if err := validateInviteShape(invite); err == nil {
		t.Fatal("validateInviteShape accepted a path invite_id")
	}
	if _, err := Load(t.TempDir(), "../../../tmp"); err == nil {
		t.Fatal("Load accepted a path invite_id")
	}
}

func TestStoreRejectsTraversalInviteID(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "evil.json")
	_ = os.Remove(outside)
	err := Store(root, Record{Invite: Invite{InviteID: "../evil"}})
	if err == nil {
		t.Fatal("Store accepted a traversal invite_id")
	}
	if _, err := os.Lstat(outside); err == nil {
		t.Fatal("Store wrote outside the invite directory")
	}
}
