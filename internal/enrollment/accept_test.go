package enrollment

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestAcceptResumesPendingAuthorizationWithoutBurningInvite(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "retry-client",
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
	request := EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           invite.Nonce,
		ClientName:      invite.ClientName,
		PublicKey:       testCompositePublicKey(),
		ProfileID:       profile.CurrentID,
		TunnelID:        "retry-client",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	}
	input := AcceptInput{
		Directory:        invites,
		ClientsDirectory: clients,
		Request:          request,
		HostPublicKey:    invite.HostPublicKey,
		Principal:        invite.Principal,
		ProfileID:        profile.CurrentID,
		TargetAddress:    invite.TargetAddress,
		TargetPort:       invite.TargetPort,
		Published:        publishedFromInvite(t, invite),
		Now:              now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error {
			return errors.New("injected authorization failure")
		},
	}
	if _, err := Accept(input); err == nil {
		t.Fatal("Accept succeeded despite injected authorization failure")
	}
	storedInvite, err := Load(invites, invite.InviteID)
	if err != nil {
		t.Fatalf("Load invite: %v", err)
	}
	if storedInvite.Status != StatusIssued {
		t.Fatalf("invite status=%q, want issued", storedInvite.Status)
	}
	clientID := clientIDFor(invite.InviteID, request.PublicKey)
	pending, err := LoadClient(clients, clientID)
	if err != nil {
		t.Fatalf("LoadClient pending: %v", err)
	}
	if pending.Status != ClientStatusEnrollmentPending {
		t.Fatalf("client status=%q, want enrollment_pending", pending.Status)
	}

	installCalls := 0
	input.InstallAuthorization = func(got string, _ time.Time) error {
		installCalls++
		if got != request.PublicKey {
			t.Fatalf("authorization key mismatch")
		}
		return nil
	}
	result, err := Accept(input)
	if err != nil {
		t.Fatalf("Accept retry: %v", err)
	}
	if installCalls != 1 || result.ClientID != clientID {
		t.Fatalf("retry calls=%d result=%+v", installCalls, result)
	}
	active, err := LoadClient(clients, clientID)
	if err != nil {
		t.Fatalf("LoadClient active: %v", err)
	}
	if active.Status != ClientStatusActive {
		t.Fatalf("client status=%q, want active", active.Status)
	}
	consumed, err := Load(invites, invite.InviteID)
	if err != nil {
		t.Fatalf("Load consumed invite: %v", err)
	}
	if consumed.Status != StatusConsumed {
		t.Fatalf("invite status=%q, want consumed", consumed.Status)
	}

	if _, err := Accept(input); err != nil {
		t.Fatalf("exact response-loss retry: %v", err)
	}
	if installCalls != 2 {
		t.Fatalf("exact retry did not reconcile authorization: calls=%d", installCalls)
	}

	// Simulate the durable boundary where client activation and authorization
	// succeeded but the final invite-consumption write did not. Exact retry must
	// converge from the already-active record rather than conflict with itself.
	consumed.Status = StatusIssued
	consumed.ClientID = ""
	consumed.ConsumedAt = ""
	if err := writeJSONAtomic(recordPath(invites, invite.InviteID), consumed, 0o600); err != nil {
		t.Fatalf("restore issued invite fixture: %v", err)
	}
	if _, err := Accept(input); err != nil {
		t.Fatalf("active-client/final-invite-write retry: %v", err)
	}
	finalInvite, err := Load(invites, invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if finalInvite.Status != StatusConsumed || installCalls != 3 {
		t.Fatalf("final invite=%+v install calls=%d", finalInvite, installCalls)
	}
}

func TestAcceptConsumesInviteOnce(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 14, 18, 0, 0, 0, time.UTC)
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
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}

	publicKey := testCompositePublicKey()
	request := EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           invite.Nonce,
		ClientName:      invite.ClientName,
		PublicKey:       publicKey,
		ProfileID:       profile.CurrentID,
		TunnelID:        "laptop-1",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	}
	result, err := Accept(AcceptInput{
		Directory:     directory,
		Request:       request,
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Published:     publishedFromInvite(t, invite),
		Now:           now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := ValidateEnrollmentProof(result.Proof, invite, publicKey); err != nil {
		t.Fatalf("ValidateEnrollmentProof: %v", err)
	}
	if _, err := Accept(AcceptInput{
		Directory:     directory,
		Request:       request,
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Published:     publishedFromInvite(t, invite),
		Now:           now.Add(2 * time.Minute),
		InstallAuthorization: func(string, time.Time) error {
			return nil
		},
	}); err == nil {
		t.Fatal("Accept allowed reuse")
	}
}

func TestAcceptRejectsNonceMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 14, 18, 30, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:                  "node-a",
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
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	noncePrefix := "00"
	if invite.Nonce[:2] == noncePrefix {
		noncePrefix = "ff"
	}
	request := EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           noncePrefix + invite.Nonce[2:],
		ClientName:      invite.ClientName,
		PublicKey:       testCompositePublicKey(),
		ProfileID:       profile.CurrentID,
		TunnelID:        "node-a",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	}
	if _, err := Accept(AcceptInput{
		Directory:     directory,
		Request:       request,
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Published:     publishedFromInvite(t, invite),
		Now:           now.Add(time.Minute),
		InstallAuthorization: func(string, time.Time) error {
			return nil
		},
	}); err == nil {
		t.Fatal("Accept accepted nonce mismatch")
	}
}

func TestEnrollmentHTTPHandlerAcceptsValidRequest(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	invite, record, err := Create(CreateInput{
		ClientName:                  "studio-mac",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   server.DefaultDedicatedUser,
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "darwin-arm64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		Now:                         now,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	authPath := filepath.Join(directory, "authorized_keys")
	manifest := validServerManifestForEnrollment()

	publicKey := testCompositePublicKey()
	request := EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           invite.Nonce,
		ClientName:      invite.ClientName,
		PublicKey:       publicKey,
		ProfileID:       profile.CurrentID,
		TunnelID:        "studio-mac",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	}
	body, err := EncodeEnrollmentRequest(request)
	if err != nil {
		t.Fatalf("EncodeEnrollmentRequest: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", func(writer http.ResponseWriter, httpRequest *http.Request) {
		var enrollRequest EnrollmentRequest
		if err := json.NewDecoder(httpRequest.Body).Decode(&enrollRequest); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		line, err := server.RenderAuthorizedKey(manifest, []byte(enrollRequest.PublicKey), time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := Accept(AcceptInput{
			Directory:     directory,
			Request:       enrollRequest,
			HostPublicKey: invite.HostPublicKey,
			Principal:     invite.Principal,
			ProfileID:     profile.CurrentID,
			TargetAddress: invite.TargetAddress,
			TargetPort:    invite.TargetPort,
			Published:     publishedFromInvite(t, invite),
			Now:           time.Now().UTC(),
			InstallAuthorization: func(string, time.Time) error {
				return os.WriteFile(authPath, line, 0o600)
			},
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(result.Proof)
	})

	response := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	mux.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var proof EnrollmentProof
	if err := json.Unmarshal(response.Body.Bytes(), &proof); err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	if err := ValidateEnrollmentProof(proof, invite, publicKey); err != nil {
		t.Fatalf("ValidateEnrollmentProof: %v", err)
	}
	if _, err := os.Stat(authPath); err != nil {
		t.Fatalf("authorized_keys missing: %v", err)
	}
}

func TestEnrollmentURL(t *testing.T) {
	t.Parallel()

	url, err := EnrollmentURL("192.0.2.10", DefaultEnrollmentPort)
	if err != nil {
		t.Fatalf("EnrollmentURL: %v", err)
	}
	if url != "https://192.0.2.10:29722/v1/enroll" {
		t.Fatalf("url=%s", url)
	}
	url, err = EnrollmentURL("2001:db8::10", DefaultEnrollmentPort)
	if err != nil {
		t.Fatalf("EnrollmentURL ipv6: %v", err)
	}
	if url != "https://[2001:db8::10]:29722/v1/enroll" {
		t.Fatalf("url=%s", url)
	}
}

func testCompositePublicKey() string {
	algorithm := "ssh-mldsa44-ed25519@openssh.com"
	rawSize := 1344
	name := []byte(algorithm)
	blob := make([]byte, 4+len(name)+4+rawSize)
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(rawSize))
	for index := 0; index < rawSize; index++ {
		blob[offset+4+index] = byte(index)
	}
	return algorithm + " " + base64.StdEncoding.EncodeToString(blob)
}

func validServerManifestForEnrollment() server.Config {
	return server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		OpenSSHBundleManifestSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Network:                     server.PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722),
		Target: server.Endpoint{
			Address: netip.MustParseAddr("198.51.100.20"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: filepath.Join(installlayout.AuthorizedKeysDirectory, server.DefaultDedicatedUser),
	}
}
