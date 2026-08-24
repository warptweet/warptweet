package enrollment

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/locator"
	"warptweet.com/warptweet/internal/profile"
)

func TestEnrollmentRequestDoesNotCarryPublishedSet(t *testing.T) {
	t.Parallel()

	raw, err := EncodeEnrollmentRequest(EnrollmentRequest{
		InviteID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Nonce:           "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ClientName:      "laptop-1",
		PublicKey:       testCompositePublicKey(),
		ProfileID:       profile.CurrentID,
		TunnelID:        "laptop-1",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"published_endpoint_generation",
		`"data"`,
		`"enrollment"`,
		"server_address",
		"enroll_port",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("EnrollmentRequest JSON contains %s: %s", forbidden, raw)
		}
	}
}

func TestValidateEnrollmentProofRequiresCompletePublishedSet(t *testing.T) {
	t.Parallel()

	invite := Invite{
		InviteID:                     "id1",
		ClientName:                   "node-a",
		Data:                         InviteDial{Host: "192.0.2.10", Port: 2222},
		Enrollment:                   InviteEnrollment{Host: "192.0.2.10", Port: 29722, TLSSPKISHA256: testEnrollmentTLSSPKIPin},
		PublishedEndpointGeneration:  1,
		TargetAddress:                "198.51.100.20",
		TargetPort:                   5432,
		Principal:                    "warptweet",
		ProfileID:                    profile.CurrentID,
		HostPublicKey:                "ssh-mldsa44-ed25519@openssh.com AAAA",
		Nonce:                        "n1",
		AuthorizationDurationSeconds: 2592000,
	}
	set := publishedFromInvite(t, invite)
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
		PublishedEndpointSet:         set,
	}
	if err := ValidateEnrollmentProof(proof, invite, proof.PublicKey); err != nil {
		t.Fatalf("valid proof: %v", err)
	}

	relocated := proof
	relocated.Data.Host = locator.IPDialHost(netip.MustParseAddr("198.51.100.10"))
	if err := ValidateEnrollmentProof(relocated, invite, proof.PublicKey); err == nil {
		t.Fatal("accepted proof that replaced the invite data locator")
	}

	generation := proof
	generation.PublishedEndpointSet.Generation = 2
	if err := ValidateEnrollmentProof(generation, invite, proof.PublicKey); err == nil {
		t.Fatal("accepted proof that replaced published_endpoint_generation")
	}

	enrollPort := proof
	enrollPort.Enrollment.Port = 8443
	if err := ValidateEnrollmentProof(enrollPort, invite, proof.PublicKey); err == nil {
		t.Fatal("accepted proof that replaced the invite enrollment port")
	}

	missing := proof
	missing.PublishedEndpointSet = locator.PublishedEndpointSet{}
	if err := ValidateEnrollmentProof(missing, invite, proof.PublicKey); err == nil {
		t.Fatal("accepted proof without a published set")
	}
}

func TestAcceptProofUsesInputSetNotRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	invite, record, err := Create(authorityCreateInput(now))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatal(err)
	}
	set := publishedFromInvite(t, invite)
	request := EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           invite.Nonce,
		ClientName:      invite.ClientName,
		PublicKey:       testCompositePublicKey(),
		ProfileID:       profile.CurrentID,
		TunnelID:        "laptop-1",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	}
	result, err := Accept(AcceptInput{
		Directory:            directory,
		ClientsDirectory:     t.TempDir(),
		Request:              request,
		HostPublicKey:        invite.HostPublicKey,
		Principal:            invite.Principal,
		ProfileID:            profile.CurrentID,
		TargetAddress:        invite.TargetAddress,
		TargetPort:           invite.TargetPort,
		Published:            set,
		Now:                  now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error { return nil },
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !result.Proof.PublishedEndpointSet.Equal(set) {
		t.Fatalf("proof set %+v want %+v", result.Proof.PublishedEndpointSet, set)
	}
	if err := ValidateEnrollmentProof(result.Proof, invite, request.PublicKey); err != nil {
		t.Fatalf("ValidateEnrollmentProof: %v", err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "published_endpoint_generation") {
		t.Fatalf("request carried a published set: %s", encoded)
	}
}

func TestAcceptRejectsPublishedSetMismatchBeforeConsume(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	invite, record, err := Create(authorityCreateInput(now))
	if err != nil {
		t.Fatal(err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatal(err)
	}
	set := publishedFromInvite(t, invite)
	set.Generation = 2
	installed := false
	_, err = Accept(AcceptInput{
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
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Published:     set,
		Now:           now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error {
			installed = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("Accept installed a published set that did not match the invite")
	}
	if installed {
		t.Fatal("authorization installed before published-set equality")
	}
	stored, err := Load(invites, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != StatusIssued {
		t.Fatalf("invite status=%q, want issued", stored.Status)
	}
	if records, err := ListClients(clients); err != nil {
		t.Fatal(err)
	} else if len(records) != 0 {
		t.Fatalf("client records=%d, want none", len(records))
	}
}

func TestStoreOrResumePendingClientComparesEntirePublishedSet(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	invite, record, err := Create(authorityCreateInput(now))
	if err != nil {
		t.Fatal(err)
	}
	invites := t.TempDir()
	clients := t.TempDir()
	if err := Store(invites, record); err != nil {
		t.Fatal(err)
	}
	set := publishedFromInvite(t, invite)
	injected := errors.New("injected authorization failure")
	input := AcceptInput{
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
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Published:     set,
		Now:           now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error {
			return injected
		},
	}
	if _, err := Accept(input); err == nil {
		t.Fatal("expected injected authorization failure")
	}
	clientID := clientIDFor(invite.InviteID, input.Request.PublicKey)
	pending, err := LoadClient(clients, clientID)
	if err != nil {
		t.Fatal(err)
	}
	pending.PublishedEndpointSet.Generation = 2
	if err := UpdateClient(clients, pending); err != nil {
		t.Fatal(err)
	}
	input.InstallAuthorization = func(string, time.Time) error { return nil }
	if _, err := Accept(input); err == nil {
		t.Fatal("re-accept treated a new published_endpoint_generation as identical")
	}
	issued, err := Load(invites, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Status != StatusIssued {
		t.Fatalf("invite status=%q, want issued", issued.Status)
	}
}

func authorityCreateInput(now time.Time) CreateInput {
	return CreateInput{
		ClientName:                  "laptop-1",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		Now:                         now,
	}
}
