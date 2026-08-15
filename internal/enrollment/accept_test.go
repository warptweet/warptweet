package enrollment

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

func TestAcceptConsumesInviteOnce(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 14, 18, 0, 0, 0, time.UTC)
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
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}

	publicKey := testCompositePublicKey()
	request := EnrollmentRequest{
		InviteID:      invite.InviteID,
		Nonce:         invite.Nonce,
		ClientName:    invite.ClientName,
		PublicKey:     publicKey,
		ProfileID:     profile.CurrentID,
		TunnelID:      "laptop-1",
		ListenAddress: "127.0.0.1",
		ListenPort:    15432,
	}
	result, err := Accept(AcceptInput{
		Directory:     directory,
		Request:       request,
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
		Now:           now.Add(2 * time.Minute),
	}); err == nil {
		t.Fatal("Accept allowed reuse")
	}
}

func TestAcceptRejectsNonceMismatch(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Date(2026, 8, 14, 18, 30, 0, 0, time.UTC)
	invite, record, err := Create(CreateInput{
		ClientName:        "node-a",
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
	directory := t.TempDir()
	if err := Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	request := EnrollmentRequest{
		InviteID:      invite.InviteID,
		Nonce:         "00" + invite.Nonce[2:],
		ClientName:    invite.ClientName,
		PublicKey:     testCompositePublicKey(),
		ProfileID:     profile.CurrentID,
		TunnelID:      "node-a",
		ListenAddress: "127.0.0.1",
		ListenPort:    15432,
	}
	if _, err := Accept(AcceptInput{
		Directory:     directory,
		Request:       request,
		HostPublicKey: invite.HostPublicKey,
		Principal:     invite.Principal,
		ProfileID:     profile.CurrentID,
		TargetAddress: invite.TargetAddress,
		TargetPort:    invite.TargetPort,
		Now:           now.Add(time.Minute),
	}); err == nil {
		t.Fatal("Accept accepted nonce mismatch")
	}
}

func TestEnrollmentHTTPHandlerAcceptsValidRequest(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Now().UTC()
	invite, record, err := Create(CreateInput{
		ClientName:        "studio-mac",
		ServerAddress:     netip.MustParseAddr("192.0.2.10"),
		ServerPort:        2222,
		TargetAddress:     netip.MustParseAddr("198.51.100.20"),
		TargetPort:        5432,
		Principal:         server.DefaultDedicatedUser,
		ProfileID:         profile.CurrentID,
		ArtifactProfileID: "darwin-arm64",
		HostPublicKey:     "ssh-mldsa44-ed25519@openssh.com AAAA host",
		Now:               now,
		Secret:            secret,
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
		InviteID:      invite.InviteID,
		Nonce:         invite.Nonce,
		ClientName:    invite.ClientName,
		PublicKey:     publicKey,
		ProfileID:     profile.CurrentID,
		TunnelID:      "studio-mac",
		ListenAddress: "127.0.0.1",
		ListenPort:    15432,
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
		line, err := server.RenderAuthorizedKey(manifest, []byte(enrollRequest.PublicKey))
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
			Now:           time.Now().UTC(),
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		if err := os.WriteFile(authPath, line, 0o600); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
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
	if url != "http://192.0.2.10:29722/v1/enroll" {
		t.Fatalf("url=%s", url)
	}
	url, err = EnrollmentURL("2001:db8::10", DefaultEnrollmentPort)
	if err != nil {
		t.Fatalf("EnrollmentURL ipv6: %v", err)
	}
	if url != "http://[2001:db8::10]:29722/v1/enroll" {
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
		Listen: server.Endpoint{
			Address: netip.MustParseAddr("192.0.2.10"),
			Port:    2222,
		},
		Target: server.Endpoint{
			Address: netip.MustParseAddr("198.51.100.20"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: filepath.Join(installlayout.AuthorizedKeysDirectory, server.DefaultDedicatedUser),
	}
}
