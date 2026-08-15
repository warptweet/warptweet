package enrollment

import (
	"context"
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

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
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

	invite, record, err := Create(CreateInput{
		ClientName:        "studio-mac",
		ServerAddress:     netip.MustParseAddr("127.0.0.1"),
		ServerPort:        2222,
		EnrollPort:        enrollPort,
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
		line, err := server.RenderAuthorizedKey(manifest, []byte(manage.NewPublicKey))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		record, token, err := RotateClientPublicKey(clientsDir, manage, manage.NewPublicKey, time.Now().UTC())
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		if err := os.WriteFile(authPath, line, 0o600); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSONResponse(writer, EnrollmentProof{
			InviteID:        record.InviteID,
			ClientID:        record.ClientID,
			HostPublicKey:   invite.HostPublicKey,
			PublicKey:       record.PublicKey,
			Target:          "198.51.100.20:5432",
			Principal:       record.Principal,
			ProfileID:       record.ProfileID,
			Nonce:           "",
			AcceptedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			ManagementToken: token,
			ServerAddress:   "127.0.0.1",
			EnrollPort:      enrollPort,
		})
	})
	mux.HandleFunc("/v1/revoke", func(writer http.ResponseWriter, httpRequest *http.Request) {
		body, _ := io.ReadAll(httpRequest.Body)
		var manage ManagementRequest
		if err := json.Unmarshal(body, &manage); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		record, err := RevokeClient(clientsDir, manage, time.Now().UTC())
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		_ = os.WriteFile(authPath, nil, 0o600)
		writeJSONResponse(writer, map[string]any{
			"status":     "revoked",
			"client_id":  record.ClientID,
			"tunnel_id":  record.TunnelID,
			"revoked_at": record.RevokedAt,
		})
	})

	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(listener) }()
	defer httpServer.Close()

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
	proof, err := SubmitEnrollment(context.Background(), invite, request)
	if err != nil {
		t.Fatalf("SubmitEnrollment: %v", err)
	}
	if proof.ManagementToken == "" || proof.ClientID == "" {
		t.Fatalf("proof incomplete: %+v", proof)
	}
	if _, err := SubmitEnrollment(context.Background(), invite, request); err == nil {
		t.Fatal("second enroll reused invite")
	}

	rotatedKey := testCompositePublicKeyRotated()
	rotated, err := SubmitRotate(context.Background(), "127.0.0.1", enrollPort, ManagementRequest{
		ClientID:        proof.ClientID,
		ManagementToken: proof.ManagementToken,
		TunnelID:        "studio-mac",
		NewPublicKey:    rotatedKey,
	})
	if err != nil {
		t.Fatalf("SubmitRotate: %v", err)
	}
	if rotated.ManagementToken == "" || rotated.ManagementToken == proof.ManagementToken {
		t.Fatal("rotate did not issue a new token")
	}
	if rotated.PublicKey != rotatedKey {
		t.Fatalf("rotated key=%q", rotated.PublicKey)
	}

	if err := SubmitRevoke(context.Background(), "127.0.0.1", enrollPort, ManagementRequest{
		ClientID:        proof.ClientID,
		ManagementToken: rotated.ManagementToken,
		TunnelID:        "studio-mac",
	}); err != nil {
		t.Fatalf("SubmitRevoke: %v", err)
	}
	if err := SubmitRevoke(context.Background(), "127.0.0.1", enrollPort, ManagementRequest{
		ClientID:        proof.ClientID,
		ManagementToken: rotated.ManagementToken,
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

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Now().UTC()
	invitesDir := t.TempDir()
	clientsDir := t.TempDir()
	manifest := validServerManifestForEnrollment()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	enrollPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	invite, record, err := Create(CreateInput{
		ClientName:        "node-a",
		ServerAddress:     netip.MustParseAddr("127.0.0.1"),
		ServerPort:        2222,
		EnrollPort:        enrollPort,
		TargetAddress:     netip.MustParseAddr("198.51.100.20"),
		TargetPort:        5432,
		Principal:         server.DefaultDedicatedUser,
		ProfileID:         profile.CurrentID,
		ArtifactProfileID: "linux-amd64",
		HostPublicKey:     "ssh-mldsa44-ed25519@openssh.com AAAA host",
		Now:               now,
		Secret:            secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := Store(invitesDir, record); err != nil {
		t.Fatalf("Store: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", newTestEnrollHandler(invite, invitesDir, clientsDir, "", manifest))
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(listener) }()
	defer httpServer.Close()

	base := EnrollmentRequest{
		InviteID:      invite.InviteID,
		Nonce:         invite.Nonce,
		ClientName:    invite.ClientName,
		PublicKey:     testCompositePublicKey(),
		ProfileID:     profile.CurrentID,
		TunnelID:      "node-a",
		ListenAddress: "127.0.0.1",
		ListenPort:    15432,
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
		line, err := server.RenderAuthorizedKey(manifest, []byte(request.PublicKey))
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
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusForbidden)
			return
		}
		if authPath != "" {
			if err := os.WriteFile(authPath, line, 0o600); err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
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
