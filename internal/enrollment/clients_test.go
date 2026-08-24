package enrollment

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/profile"
)

func TestAcceptStoresClientAndRevokeBurnsToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 14, 20, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "laptop-1",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		Now:                         now,
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
		Published:            publishedFromInvite(t, invite),
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
	clientInfo, err := os.Stat(clientPath(clients, result.ClientID))
	if err != nil {
		t.Fatalf("stat client record: %v", err)
	}
	if clientInfo.Mode().Perm() != 0o640 {
		t.Fatalf("client record mode=%o want 0640", clientInfo.Mode().Perm())
	}

	revokeRequest := ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: testManagementToken,
		TunnelID:        "laptop-1",
	}
	if _, err := RevokeClient(clients, revokeRequest, now.Add(2*time.Minute), func(string) error {
		return errors.New("injected authorization removal failure")
	}, SessionEnforcement{}); err == nil {
		t.Fatal("RevokeClient succeeded despite injected authorization failure")
	}
	pendingRevoke, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatalf("LoadClient pending revoke: %v", err)
	}
	if pendingRevoke.Status != ClientStatusRevocationPending {
		t.Fatalf("status=%s, want revocation_pending", pendingRevoke.Status)
	}
	if _, err := RevokeClient(clients, revokeRequest, now.Add(2*time.Minute), func(string) error { return nil }, SessionEnforcement{
		TerminateSession: func(string, string, string) error {
			return errors.New("injected session terminate failure")
		},
		VerifySessionGone: func(string, string, string) error {
			t.Fatal("VerifySessionGone ran after TerminateSession failed")
			return nil
		},
	}); err == nil {
		t.Fatal("RevokeClient succeeded despite injected session terminate failure")
	}
	pendingSession, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatalf("LoadClient pending session: %v", err)
	}
	if pendingSession.Status != ClientStatusRevocationPending {
		t.Fatalf("status=%s, want revocation_pending after session hook failure", pendingSession.Status)
	}
	var hooks []string
	revoked, err := RevokeClient(clients, revokeRequest, now.Add(2*time.Minute), func(string) error { return nil }, SessionEnforcement{
		TerminateSession: func(clientID, generation, publicKeySHA256 string) error {
			if clientID != loaded.ClientID || generation != "" || publicKeySHA256 != "" {
				t.Fatalf("terminate args=%s %s %s", clientID, generation, publicKeySHA256)
			}
			hooks = append(hooks, "terminate")
			return nil
		},
		VerifySessionGone: func(clientID, generation, publicKeySHA256 string) error {
			if clientID != loaded.ClientID || generation != "" || publicKeySHA256 != "" {
				t.Fatalf("verify args=%s %s %s", clientID, generation, publicKeySHA256)
			}
			hooks = append(hooks, "verify")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	if revoked.Status != ClientStatusRevoked {
		t.Fatalf("status=%s", revoked.Status)
	}
	if got := strings.Join(hooks, ","); got != "terminate,verify" {
		t.Fatalf("session hooks=%q, want terminate then verify", got)
	}
	again, err := RevokeClient(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: testManagementToken,
		TunnelID:        "laptop-1",
	}, now.Add(3*time.Minute), func(string) error { return nil }, SessionEnforcement{})
	if err != nil {
		t.Fatalf("second RevokeClient should be idempotent: %v", err)
	}
	if again.Status != ClientStatusRevoked || again.ClientID != result.ClientID {
		t.Fatalf("second revoke record=%+v", again)
	}
}

func TestRevokeClientAsHostDoesNotNeedBearerToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 22, 20, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "host-revoke",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		Now:                         now,
	})
	if err != nil {
		t.Fatal(err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatal(err)
	}
	accepted, err := Accept(AcceptInput{
		Directory:        invites,
		ClientsDirectory: clients,
		Request: EnrollmentRequest{
			InviteID:        invite.InviteID,
			Nonce:           invite.Nonce,
			ClientName:      invite.ClientName,
			PublicKey:       testCompositePublicKey(),
			ProfileID:       profile.CurrentID,
			TunnelID:        "host-revoke",
			ListenAddress:   "127.0.0.1",
			ListenPort:      15432,
			ManagementToken: testManagementToken,
		},
		HostPublicKey:        invite.HostPublicKey,
		Principal:            invite.Principal,
		ProfileID:            profile.CurrentID,
		TargetAddress:        invite.TargetAddress,
		TargetPort:           invite.TargetPort,
		Published:            publishedFromInvite(t, invite),
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RevokeClientAsHost(clients, accepted.ClientID, now.Add(2*time.Minute), nil, SessionEnforcement{}); err == nil {
		t.Fatal("nil removeAuthorization accepted")
	}
	unchanged, err := LoadClient(clients, accepted.ClientID)
	if err != nil || unchanged.Status != ClientStatusActive {
		t.Fatalf("nil callback mutated record: %+v %v", unchanged, err)
	}
	var removed bool
	revoked, err := RevokeClientAsHost(clients, accepted.ClientID, now.Add(2*time.Minute), func(string) error {
		removed = true
		return nil
	}, SessionEnforcement{
		TerminateSession:  func(string, string, string) error { return nil },
		VerifySessionGone: func(string, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !removed || revoked.Status != ClientStatusRevoked {
		t.Fatalf("removed=%v status=%s", removed, revoked.Status)
	}
	if revoked.ManagementTokenSHA256 == HashManagementToken(testManagementToken) {
		t.Fatal("host revoke did not burn the management token")
	}
}

func TestRevokeClientAsHostRemovesPendingRotationKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 22, 21, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "pending-rotate",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		Now:                         now,
	})
	if err != nil {
		t.Fatal(err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatal(err)
	}
	accepted, err := Accept(AcceptInput{
		Directory:        invites,
		ClientsDirectory: clients,
		Request: EnrollmentRequest{
			InviteID:        invite.InviteID,
			Nonce:           invite.Nonce,
			ClientName:      invite.ClientName,
			PublicKey:       testCompositePublicKey(),
			ProfileID:       profile.CurrentID,
			TunnelID:        "pending-rotate",
			ListenAddress:   "127.0.0.1",
			ListenPort:      15432,
			ManagementToken: testManagementToken,
		},
		HostPublicKey:        invite.HostPublicKey,
		Principal:            invite.Principal,
		ProfileID:            profile.CurrentID,
		TargetAddress:        invite.TargetAddress,
		TargetPort:           invite.TargetPort,
		Published:            publishedFromInvite(t, invite),
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RotateClientPublicKey(clients, ManagementRequest{
		ClientID:            accepted.ClientID,
		ManagementToken:     testManagementToken,
		TunnelID:            "pending-rotate",
		NextManagementToken: testNextManagementToken,
	}, testCompositePublicKeyRotated(), now.Add(2*time.Minute), func(string, string) error {
		return errors.New("leave rotation pending")
	}); err == nil {
		t.Fatal("expected pending rotation")
	}
	var removed []string
	revoked, err := RevokeClientAsHost(clients, accepted.ClientID, now.Add(3*time.Minute), func(publicKey string) error {
		removed = append(removed, publicKey)
		return nil
	}, SessionEnforcement{})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != ClientStatusRevoked || revoked.PendingPublicKey != "" || revoked.PendingManagementTokenSHA256 != "" {
		t.Fatalf("revoked pending fields remain: %+v", revoked)
	}
	if len(removed) != 2 {
		t.Fatalf("removed keys=%d, want current and pending", len(removed))
	}
}

func TestReconcilePendingRevocationsCompletesStuckRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 14, 20, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "laptop-1",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		Now:                         now,
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
		Published:            publishedFromInvite(t, invite),
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := RevokeClient(clients, ManagementRequest{
		ClientID:        result.ClientID,
		ManagementToken: testManagementToken,
		TunnelID:        "laptop-1",
	}, now.Add(2*time.Minute), func(string) error {
		return errors.New("injected authorization removal failure")
	}, SessionEnforcement{}); err == nil {
		t.Fatal("expected injected failure")
	}
	var terminated, verified int
	if err := ReconcilePendingRevocations(clients, now.Add(3*time.Minute), func(string) error { return nil }, SessionEnforcement{
		TerminateSession: func(string, string, string) error {
			terminated++
			return nil
		},
		VerifySessionGone: func(string, string, string) error {
			verified++
			return nil
		},
	}); err != nil {
		t.Fatalf("ReconcilePendingRevocations: %v", err)
	}
	if terminated != 1 || verified != 1 {
		t.Fatalf("session hooks terminate=%d verify=%d", terminated, verified)
	}
	loaded, err := LoadClient(clients, result.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != ClientStatusRevoked {
		t.Fatalf("status=%s, want revoked", loaded.Status)
	}
}

func TestRotateClientIssuesNewToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 14, 21, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "studio-mac",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		Now:                         now,
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
		Published:            publishedFromInvite(t, invite),
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
	var evicted []string
	if err := EvictPreviousKeySessions(updated, SessionEnforcement{
		TerminateSession: func(clientID, generation, publicKeySHA256 string) error {
			if clientID != result.ClientID || publicKeySHA256 != PublicKeyDigest(firstKey) {
				t.Fatalf("evicted unexpected session client=%s key=%s", clientID, publicKeySHA256)
			}
			evicted = append(evicted, publicKeySHA256)
			return nil
		},
		VerifySessionGone: func(clientID, generation, publicKeySHA256 string) error {
			if len(evicted) == 0 {
				t.Fatal("VerifySessionGone ran before TerminateSession")
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("EvictPreviousKeySessions: %v", err)
	}
	if len(evicted) != 1 {
		t.Fatalf("old-key sessions evicted %d times, want 1", len(evicted))
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

	now := time.Date(2026, 8, 14, 21, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                   "studio-mac",
		DataHost:                     "192.0.2.10",
		DataPort:                     2222,
		EnrollmentHost:               "192.0.2.10",
		EnrollmentPort:               DefaultEnrollmentPort,
		PublishedEndpointGeneration:  1,
		TargetAddress:                netip.MustParseAddr("198.51.100.20"),
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    profile.CurrentID,
		ArtifactProfileID:            "linux-amd64",
		HostPublicKey:                "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:      testEnrollmentTLSSPKIPin,
		AuthorizationDurationSeconds: 3600,
		Now:                          now,
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
		Published:            publishedFromInvite(t, invite),
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

func TestEnsureClientsDirectoryPreservesSetgid(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "clients")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	if err := ensureClientsDirectory(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatal("ensureClientsDirectory stripped setgid")
	}
}
