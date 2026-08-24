package enrollment

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestSubmitEnrollmentRotateRevokeRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	invitesDir := t.TempDir()
	clientsDir := t.TempDir()
	authPath := filepath.Join(t.TempDir(), "authorized_keys")
	manifest := validServerManifestForEnrollment()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	enrollPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	certPath := filepath.Join(t.TempDir(), "tls.crt")
	keyPath := filepath.Join(t.TempDir(), "tls.key")
	enrollmentPin, _, _, err := EnsureTLSIdentity(certPath, keyPath, []net.IP{net.ParseIP("127.0.0.1")}, now)
	if err != nil {
		t.Fatalf("EnsureTLSIdentity: %v", err)
	}

	invite, record, err := Create(CreateInput{
		ClientName:                  "studio-mac",
		DataHost:                    "127.0.0.1",
		DataPort:                    2222,
		EnrollmentHost:              "127.0.0.1",
		EnrollmentPort:              enrollPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   server.DefaultDedicatedUser,
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "darwin-arm64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     enrollmentPin,
		Now:                         now,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := Store(invitesDir, record); err != nil {
		t.Fatalf("Store: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", newTestEnrollHandler(invite, invitesDir, clientsDir, authPath, manifest))
	mux.HandleFunc("/v1/rotate", func(writer http.ResponseWriter, httpRequest *http.Request) {
		body, _ := io.ReadAll(httpRequest.Body)
		var manage ManagementRequest
		if err := json.Unmarshal(body, &manage); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		line, err := server.RenderAuthorizedKey(manifest, []byte(manage.NewPublicKey), time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		record, err := RotateClientPublicKey(clientsDir, manage, manage.NewPublicKey, time.Now().UTC(), func(string, string) error {
			return os.WriteFile(authPath, line, 0o644)
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		writeJSONResponse(writer, EnrollmentProof{
			InviteID:      record.InviteID,
			ClientID:      record.ClientID,
			HostPublicKey: invite.HostPublicKey,
			PublicKey:     record.PublicKey,
			Target:        "198.51.100.20:5432",
			Principal:     record.Principal,
			ProfileID:     record.ProfileID,
			Nonce:         "",
			AcceptedAt:    time.Now().UTC().Format(time.RFC3339Nano),
			ServerAddress: "127.0.0.1",
			EnrollPort:    enrollPort,
		})
	})
	mux.HandleFunc("/v1/revoke", func(writer http.ResponseWriter, httpRequest *http.Request) {
		body, _ := io.ReadAll(httpRequest.Body)
		var manage ManagementRequest
		if err := json.Unmarshal(body, &manage); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		record, err := RevokeClient(clientsDir, manage, time.Now().UTC(), func(string) error {
			return os.WriteFile(authPath, nil, 0o644)
		}, SessionEnforcement{})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		writeJSONResponse(writer, map[string]any{
			"status":     "revoked",
			"client_id":  record.ClientID,
			"tunnel_id":  record.TunnelID,
			"revoked_at": record.RevokedAt,
		})
	})

	tlsConfig, err := LoadServerTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(tls.NewListener(listener, tlsConfig)) }()
	defer httpServer.Close()

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
	proof, err := SubmitEnrollment(context.Background(), invite, request)
	if err != nil {
		t.Fatalf("SubmitEnrollment: %v", err)
	}
	if proof.ClientID == "" {
		t.Fatalf("proof incomplete: %+v", proof)
	}
	if again, err := SubmitEnrollment(context.Background(), invite, request); err != nil || again.ClientID != proof.ClientID {
		t.Fatalf("exact enrollment retry did not converge: proof=%+v err=%v", again, err)
	}

	rotatedKey := testCompositePublicKeyRotated()
	rotated, err := SubmitRotate(context.Background(), "127.0.0.1", enrollPort, enrollmentPin, ManagementRequest{
		ClientID:            proof.ClientID,
		ManagementToken:     testManagementToken,
		TunnelID:            "studio-mac",
		NewPublicKey:        rotatedKey,
		NextManagementToken: testNextManagementToken,
	})
	if err != nil {
		t.Fatalf("SubmitRotate: %v", err)
	}
	if rotated.PublicKey != rotatedKey {
		t.Fatalf("rotated key=%q", rotated.PublicKey)
	}

	if err := SubmitRevoke(context.Background(), "127.0.0.1", enrollPort, enrollmentPin, ManagementRequest{
		ClientID:        proof.ClientID,
		ManagementToken: testNextManagementToken,
		TunnelID:        "studio-mac",
	}); err != nil {
		t.Fatalf("SubmitRevoke: %v", err)
	}
	if err := SubmitRevoke(context.Background(), "127.0.0.1", enrollPort, enrollmentPin, ManagementRequest{
		ClientID:        proof.ClientID,
		ManagementToken: testNextManagementToken,
		TunnelID:        "studio-mac",
	}); err != nil {
		t.Fatalf("second SubmitRevoke should be idempotent: %v", err)
	}
	contents, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if len(contents) != 0 {
		t.Fatalf("authorized_keys not cleared after revoke: %q", contents)
	}
}

func TestSubmitEnrollmentFailClosedCases(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	invitesDir := t.TempDir()
	clientsDir := t.TempDir()
	manifest := validServerManifestForEnrollment()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	enrollPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	certPath := filepath.Join(t.TempDir(), "tls.crt")
	keyPath := filepath.Join(t.TempDir(), "tls.key")
	enrollmentPin, _, _, err := EnsureTLSIdentity(certPath, keyPath, []net.IP{net.ParseIP("127.0.0.1")}, now)
	if err != nil {
		t.Fatalf("EnsureTLSIdentity: %v", err)
	}

	invite, record, err := Create(CreateInput{
		ClientName:                  "node-a",
		DataHost:                    "127.0.0.1",
		DataPort:                    2222,
		EnrollmentHost:              "127.0.0.1",
		EnrollmentPort:              enrollPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   server.DefaultDedicatedUser,
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
		EnrollmentTLSSPKISHA256:     enrollmentPin,
		Now:                         now,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := Store(invitesDir, record); err != nil {
		t.Fatalf("Store: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", newTestEnrollHandler(invite, invitesDir, clientsDir, "", manifest))
	tlsConfig, err := LoadServerTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(tls.NewListener(listener, tlsConfig)) }()
	defer httpServer.Close()

	base := EnrollmentRequest{
		InviteID:        invite.InviteID,
		Nonce:           invite.Nonce,
		ClientName:      invite.ClientName,
		PublicKey:       testCompositePublicKey(),
		ProfileID:       profile.CurrentID,
		TunnelID:        "node-a",
		ListenAddress:   "127.0.0.1",
		ListenPort:      15432,
		ManagementToken: testManagementToken,
	}

	// Wrong nonce (guaranteed different prefix from the invite nonce)
	badNonce := base
	prefix := "00"
	if len(invite.Nonce) >= 2 && invite.Nonce[:2] == prefix {
		prefix = "ff"
	}
	badNonce.Nonce = prefix + invite.Nonce[2:]
	if badNonce.Nonce == invite.Nonce {
		badNonce.Nonce = "ffffffffffffffffffffffffffffffff"
	}
	if _, err := SubmitEnrollment(context.Background(), invite, badNonce); err == nil {
		t.Fatal("accepted wrong nonce")
	}

	// Wrong invite id
	badID := base
	badID.InviteID = "ffffffffffffffffffffffffffffffff"
	if _, err := SubmitEnrollment(context.Background(), invite, badID); err == nil {
		t.Fatal("accepted unknown invite")
	}

	// Happy path still works after negatives
	if _, err := SubmitEnrollment(context.Background(), invite, base); err != nil {
		t.Fatalf("valid enroll after negatives: %v", err)
	}
}

func newTestEnrollHandler(
	invite Invite,
	invitesDir, clientsDir, authPath string,
	manifest server.Config,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, httpRequest *http.Request) {
		body, _ := io.ReadAll(httpRequest.Body)
		var request EnrollmentRequest
		if err := json.Unmarshal(body, &request); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		line, err := server.RenderAuthorizedKey(manifest, []byte(request.PublicKey), time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := Accept(AcceptInput{
			Directory:        invitesDir,
			ClientsDirectory: clientsDir,
			Request:          request,
			HostPublicKey:    invite.HostPublicKey,
			Principal:        invite.Principal,
			ProfileID:        profile.CurrentID,
			TargetAddress:    invite.TargetAddress,
			TargetPort:       invite.TargetPort,
			ServerAddress:    "127.0.0.1",
			Now:              time.Now().UTC(),
			InstallAuthorization: func(string, time.Time) error {
				if authPath == "" {
					return nil
				}
				return os.WriteFile(authPath, line, 0o644)
			},
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		writeJSONResponse(writer, result.Proof)
	}
}

func writeJSONResponse(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
