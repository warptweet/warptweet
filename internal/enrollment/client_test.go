package enrollment

import (
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/profile"
)

func TestParseClientInviteRejectsV1Schema(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	raw := []byte(`{
  "kind":"warptweet.invite",
  "schema_version":1,
  "invite_id":"abc",
  "client_name":"laptop-1",
  "server_address":"192.0.2.10",
  "server_port":2222,
  "enroll_port":29722,
  "target_address":"198.51.100.20",
  "target_port":5432,
  "principal":"warptweet",
  "profile_id":"` + profile.CurrentID + `",
  "artifact_profile_id":"linux-amd64",
  "host_public_key":"ssh-mldsa44-ed25519@openssh.com AAAA",
  "enrollment_tls_spki_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "issued_at":"2026-08-16T12:00:00Z",
  "expires_at":"2026-08-16T12:10:00Z",
  "nonce":"00",
  "mac":"aa"
}`)
	if _, _, err := ParseClientInvite(raw, now.Add(time.Minute)); err == nil {
		t.Fatal("accepted invite schema v1")
	}
}

func TestParseClientInviteRejectsSecretsAndExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	raw := []byte(`{
  "kind":"warptweet.invite",
  "schema_version":2,
  "invite_id":"abc",
  "client_name":"laptop-1",
  "server_address":"192.0.2.10",
  "server_port":2222,
  "enroll_port":29722,
  "target_address":"198.51.100.20",
  "target_port":5432,
  "principal":"warptweet",
  "profile_id":"` + profile.CurrentID + `",
  "artifact_profile_id":"linux-amd64",
  "host_public_key":"ssh-mldsa44-ed25519@openssh.com AAAA",
  "enrollment_tls_spki_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "issued_at":"2026-08-12T12:00:00Z",
  "expires_at":"2026-08-12T12:10:00Z",
  "authorization_duration_seconds":2592000,
  "nonce":"00",
  "mac":"aa"
}`)
	invite, view, err := ParseClientInvite(raw, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ParseClientInvite: %v", err)
	}
	if invite.InviteID != "abc" || view.TunnelID != "laptop-1" || view.ListenAddress != "127.0.0.1" {
		t.Fatalf("unexpected invite/view: %+v %+v", invite, view)
	}
	if _, _, err := ParseClientInvite(raw, now.Add(20*time.Minute)); err == nil {
		t.Fatal("accepted expired invite")
	}
	if _, _, err := ParseClientInvite([]byte(`{"private":"x"}`), now); err == nil {
		t.Fatal("accepted private key material")
	}
}

func TestBuildClientManifestAndProof(t *testing.T) {
	t.Parallel()

	invite := Invite{
		InviteID:                     "id1",
		ClientName:                   "node-a",
		ServerAddress:                "192.0.2.10",
		ServerPort:                   2222,
		TargetAddress:                "198.51.100.20",
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    profile.CurrentID,
		HostPublicKey:                "ssh-mldsa44-ed25519@openssh.com AAAA",
		Nonce:                        "n1",
		AuthorizationDurationSeconds: 2592000,
	}
	manifest, err := BuildClientManifest(invite, "database-primary", 15432, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("BuildClientManifest: %v", err)
	}
	if manifest.Tunnels[0].ID != "database-primary" || manifest.Server.User != "warptweet" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	proof := EnrollmentProof{
		InviteID:                     invite.InviteID,
		ClientID:                     "client-1",
		HostPublicKey:                invite.HostPublicKey,
		PublicKey:                    "ssh-mldsa44-ed25519@openssh.com BBBB",
		Target:                       "198.51.100.20:5432",
		Principal:                    invite.Principal,
		ProfileID:                    invite.ProfileID,
		Nonce:                        invite.Nonce,
		AcceptedAt:                   "2026-08-16T12:00:00Z",
		AuthorizationNotAfter:        "2026-09-15T12:00:00Z",
		AuthorizationDurationSeconds: 2592000,
	}
	if err := ValidateEnrollmentProof(proof, invite, proof.PublicKey); err != nil {
		t.Fatalf("ValidateEnrollmentProof: %v", err)
	}
	proof.Target = "10.0.0.1:1"
	if err := ValidateEnrollmentProof(proof, invite, "ssh-mldsa44-ed25519@openssh.com BBBB"); err == nil {
		t.Fatal("accepted mismatched target")
	}
}
