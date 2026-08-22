package integration_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/grantsession"
)

func TestKeyAuthenticatedSessionRemovesRegistrarRecord(t *testing.T) {
	root := t.TempDir()
	clients := filepath.Join(root, "clients")
	sessions := filepath.Join(root, "sessions")
	blob := make([]byte, 32)
	for i := range blob {
		blob[i] = byte(i + 3)
	}
	digest := sha256.Sum256(blob)
	keyDigest := hex.EncodeToString(digest[:])
	publicKey := "ssh-mldsa44-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(blob)
	notAfter, err := grant.FormatUTC(time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollment.StoreClient(clients, enrollment.ClientRecord{
		ClientID:                     "aaaaaaaaaaaaaaaa",
		GrantID:                      "bbbbbbbbbbbbbbbb",
		TunnelID:                     "staging-db",
		RouteID:                      "staging-db",
		InviteID:                     "cccccccccccccccc",
		PublicKey:                    publicKey,
		PublicKeySHA256:              enrollment.PublicKeyDigest(publicKey),
		ManagementTokenSHA256:        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Principal:                    "warptweet",
		ProfileID:                    "warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20",
		Status:                       enrollment.ClientStatusActive,
		AcceptedAt:                   "2026-08-16T12:00:00Z",
		AuthorizationNotAfter:        notAfter,
		AuthorizationDurationSeconds: 2592000,
		Generation:                   "20260816T120000Z",
		TargetAddress:                "127.0.0.1",
		TargetPort:                   5432,
	}); err != nil {
		t.Fatalf("store client: %v", err)
	}
	authority := &grantsession.Authority{
		Root:    sessions,
		Clients: clients,
		Now:     func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) },
		Inspect: func(pid int) (grantsession.ProcessIdentity, error) {
			return grantsession.ProcessIdentity{
				BootID:    "boot-1",
				PID:       pid,
				StartTime: "99",
				Exe:       "/opt/warptweet/libexec/openssh/libexec/sshd-session",
			}, nil
		},
	}
	if _, err := authority.Register(4242, keyDigest, "20260816T120000Z-4242"); err != nil {
		t.Fatalf("open key-authenticated session: %v", err)
	}
	if err := authority.Unregister(4242); err != nil {
		t.Fatalf("close key-authenticated session: %v", err)
	}
	records, err := authority.Lookup("aaaaaaaaaaaaaaaa", "20260816T120000Z", enrollment.PublicKeyDigest(publicKey))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("registrar record remained after session close: %+v", records)
	}
	patch, err := os.ReadFile(filepath.Join("..", "..", "third_party", "openssh", "patches", "0001-warptweet-grant-register.patch"))
	if err != nil {
		t.Fatalf("read patch: %v", err)
	}
	if !strings.Contains(string(patch), "mm_answer_term") || !strings.Contains(string(patch), "warptweet_grant_unregister();") {
		t.Fatal("OpenSSH patch does not unregister on normal monitor termination")
	}
}
