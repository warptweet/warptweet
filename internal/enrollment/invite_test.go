package enrollment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateParseConsumeInviteLifecycle(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	input := testCreateInput()
	input.TTL = DefaultTTL
	input.Now = now
	invite, record, err := Create(input)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if record.Status != StatusIssued || invite.InviteID == "" || invite.Nonce == "" {
		t.Fatalf("unexpected invite: %+v record=%+v", invite, record)
	}
	if invite.SchemaVersion != 3 || invite.Data.Host != "192.0.2.10" || invite.Enrollment.Host != "192.0.2.10" {
		t.Fatalf("invite=%+v", invite)
	}
	if invite.PublishedEndpointGeneration != 1 {
		t.Fatalf("generation=%d", invite.PublishedEndpointGeneration)
	}

	raw, err := Encode(invite)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(raw), "BEGIN") || strings.Contains(strings.ToLower(string(raw)), "private") {
		t.Fatal("invite encoding contains private-key markers")
	}
	if strings.Contains(string(raw), "server_address") || strings.Contains(string(raw), "enroll_port") {
		t.Fatalf("schema 3 invite still encodes schema 2 fields: %s", raw)
	}

	var parsed Invite
	if err := decodeStrictJSON(raw, &parsed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if parsed.InviteID != invite.InviteID {
		t.Fatalf("parsed id = %q", parsed.InviteID)
	}

	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	blob, err := LoadIssuedBlob(directory, invite.InviteID)
	if err != nil {
		t.Fatalf("LoadIssuedBlob: %v", err)
	}
	if string(blob) != string(raw) {
		t.Fatalf("durable blob mismatch")
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

func TestCreateCanonicalizesDNSHostCasing(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	input.DataHost = "TUNNEL.EXAMPLE.COM"
	input.DataPort = 443
	input.EnrollmentHost = "ENROLL.EXAMPLE.COM"
	input.EnrollmentPort = 8443
	invite, _, err := Create(input)
	if err != nil {
		t.Fatal(err)
	}
	if invite.Data.Host != "tunnel.example.com" || invite.Enrollment.Host != "enroll.example.com" {
		t.Fatalf("hosts=%q %q", invite.Data.Host, invite.Enrollment.Host)
	}
}

func TestCreateRejectsEqualCanonicalLocators(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	input.DataPort = DefaultEnrollmentPort
	if _, _, err := Create(input); err == nil {
		t.Fatal("accepted identical data and enrollment locators")
	}
}

func TestCreateAllowsEqualPortsOnDifferentHosts(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	input.DataHost = "tunnel.example.com"
	input.DataPort = 443
	input.EnrollmentHost = "enroll.example.com"
	input.EnrollmentPort = 443
	if _, _, err := Create(input); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeInvite(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 12, 13, 0, 0, 0, time.UTC)
	input := testCreateInput()
	input.ClientName = "laptop-2"
	input.Now = now
	invite, record, err := Create(input)
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

	now := time.Date(2026, 8, 12, 13, 0, 0, 0, time.UTC)
	input := testCreateInput()
	input.ClientName = "laptop-3"
	input.Now = now
	invite, record, err := Create(input)
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

	now := time.Date(2026, 8, 22, 20, 0, 0, 0, time.UTC)
	input := testCreateInput()
	input.ClientName = "expired-invite"
	input.Now = now
	invite, record, err := Create(input)
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

func TestStoredInviteDurationIsAuthoritative(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	input := testCreateInput()
	input.TTL = DefaultTTL
	input.AuthorizationDurationSeconds = 3600
	input.Now = now
	invite, record, err := Create(input)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if invite.SchemaVersion != 3 || invite.AuthorizationDurationSeconds != 3600 {
		t.Fatalf("invite=%+v", invite)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AuthorizationDurationSeconds != 3600 {
		t.Fatalf("stored duration=%d", loaded.AuthorizationDurationSeconds)
	}
}

func TestCreateRejectsDurationAboveMaximum(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	input.AuthorizationDurationSeconds = 31536001
	input.MaximumAuthorizationDurationSeconds = 31536000
	if _, _, err := Create(input); err == nil {
		t.Fatal("Create accepted a duration above the host maximum")
	}
}

func TestCreateRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	input.ClientName = "../evil"
	if _, _, err := Create(input); err == nil {
		t.Fatal("Create accepted unsafe client name")
	}
}

func TestInviteIDRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	invite := Invite{
		Kind:          KindInvite,
		SchemaVersion: CurrentSchemaVersion,
		InviteID:      "../../../tmp",
		ClientName:    "laptop-1",
		Data:          InviteDial{Host: "192.0.2.10", Port: 2222},
		Enrollment: InviteEnrollment{
			Host:          "192.0.2.10",
			Port:          29722,
			TLSSPKISHA256: strings.Repeat("ab", 32),
		},
		PublishedEndpointGeneration:  1,
		TargetAddress:                "198.51.100.20",
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    "profile-v1",
		Nonce:                        strings.Repeat("ab", 16),
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

func TestUnusedIssuedForGenerationResumesOneInvite(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	invite, record, err := Create(input)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	issued, err := UnusedIssuedForGeneration(directory, 1, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(issued) != 1 || issued[0].InviteID != invite.InviteID {
		t.Fatalf("issued=%+v", issued)
	}
	blob, err := LoadIssuedBlob(directory, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Encode(issued[0].Invite)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != string(again) {
		t.Fatal("resumed bytes differ")
	}
}

func TestLoadIssuedBlobResumesEncodeWhenBlobMissing(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	invite, record, err := Create(input)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(IssuedBlobPath(directory, invite.InviteID)); err != nil {
		t.Fatal(err)
	}
	blob, err := LoadIssuedBlob(directory, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(invite)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != string(encoded) {
		t.Fatal("missing-blob resume did not match Encode bytes")
	}
	issued, err := UnusedIssuedForGeneration(directory, 1, input.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(issued) != 1 || issued[0].InviteID != invite.InviteID {
		t.Fatalf("issued=%+v", issued)
	}
}

func TestUnusedIssuedForGenerationExpiresPastDueRecords(t *testing.T) {
	t.Parallel()

	input := testCreateInput()
	input.Now = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	input.TTL = time.Minute
	invite, record, err := Create(input)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	issued, err := UnusedIssuedForGeneration(directory, 1, input.Now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(issued) != 0 {
		t.Fatalf("issued expired invite: %+v", issued)
	}
	loaded, err := Load(directory, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != StatusExpired {
		t.Fatalf("status=%s", loaded.Status)
	}
}
