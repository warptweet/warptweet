package grantsession

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
)

func TestRegisterRejectsMissingAndExpiredGrants(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	clients := filepath.Join(root, "clients")
	sessions := filepath.Join(root, "sessions")
	blob := make([]byte, 32)
	for i := range blob {
		blob[i] = byte(i + 1)
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
	authority := &Authority{
		Root:    sessions,
		Clients: clients,
		Now:     func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) },
		Inspect: func(pid int) (ProcessIdentity, error) {
			return ProcessIdentity{BootID: "boot-1", PID: pid, StartTime: "99", Exe: "/opt/warptweet/libexec/openssh/libexec/sshd-session"}, nil
		},
	}
	if _, err := authority.Register(4242, keyDigest, "conn-1"); err != nil {
		t.Fatalf("register: %v", err)
	}
	authority.Now = func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) }
	if _, err := authority.Register(4243, keyDigest, "conn-2"); err == nil {
		t.Fatal("accepted expired grant")
	}
	if _, err := authority.Register(4244, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "conn-3"); err == nil {
		t.Fatal("accepted unknown key")
	}
}

func TestRegisterRejectsForeignExecutable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	clients := filepath.Join(root, "clients")
	sessions := filepath.Join(root, "sessions")
	blob := make([]byte, 32)
	for i := range blob {
		blob[i] = byte(i + 1)
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
	authority := &Authority{
		Root:        sessions,
		Clients:     clients,
		ExpectedExe: "/opt/warptweet/libexec/openssh/libexec/sshd-session",
		Now:         func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) },
		Inspect: func(pid int) (ProcessIdentity, error) {
			return ProcessIdentity{BootID: "boot-1", PID: pid, StartTime: "99", Exe: "/tmp/attack/libexec/sshd-session"}, nil
		},
	}
	if _, err := authority.Register(4242, keyDigest, "conn-1"); err == nil {
		t.Fatal("accepted foreign executable")
	}
	authority.Inspect = func(pid int) (ProcessIdentity, error) {
		return ProcessIdentity{BootID: "boot-1", PID: pid, StartTime: "99", Exe: "sshd-session"}, nil
	}
	if _, err := authority.Register(4243, keyDigest, "conn-2"); err == nil {
		t.Fatal("accepted comm-only executable")
	}
}

func TestKeyBlobDigestMatchesWireBlob(t *testing.T) {
	t.Parallel()

	blob := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	got, err := KeyBlobDigest(line)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest=%s", got)
	}
	spaced := `restrict,from="10.0.0.1 10.0.0.2",permitopen="127.0.0.1:5432" ssh-ed25519 ` + base64.StdEncoding.EncodeToString(blob)
	got, err = KeyBlobDigest(spaced)
	if err != nil {
		t.Fatalf("spaced option: %v", err)
	}
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("spaced digest=%s", got)
	}
	escaped := `restrict,from="10.0.0.1\"lab" ssh-ed25519 ` + base64.StdEncoding.EncodeToString(blob)
	if _, err := KeyBlobDigest(escaped); err != nil {
		t.Fatalf("escaped quote: %v", err)
	}
	if _, err := KeyBlobDigest(`restrict,from="unterminated ssh-ed25519 AAAA`); err == nil {
		t.Fatal("accepted unterminated quote")
	}
	managed := `restrict,port-forwarding,permitopen="127.0.0.1:5432",permitopen="127.0.0.1:29723" ssh-ed25519 ` + base64.StdEncoding.EncodeToString(blob) + " comment"
	got, err = KeyBlobDigest(managed)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("managed digest=%s", got)
	}
}

func TestRegisterAndUnregisterRemovesRecord(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	clients := filepath.Join(root, "clients")
	sessions := filepath.Join(root, "sessions")
	blob := make([]byte, 32)
	for i := range blob {
		blob[i] = byte(i + 1)
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
	authority := &Authority{
		Root:    sessions,
		Clients: clients,
		Now:     func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) },
		Inspect: func(pid int) (ProcessIdentity, error) {
			return ProcessIdentity{BootID: "boot-1", PID: pid, StartTime: "99", Exe: "/opt/warptweet/libexec/openssh/libexec/sshd-session"}, nil
		},
	}
	if _, err := authority.Register(4242, keyDigest, "20260816T120000Z-4242"); err != nil {
		t.Fatalf("register: %v", err)
	}
	records, err := authority.Lookup("aaaaaaaaaaaaaaaa", "20260816T120000Z", enrollment.PublicKeyDigest(publicKey))
	if err != nil || len(records) != 1 {
		t.Fatalf("lookup after register records=%d err=%v", len(records), err)
	}
	if _, err := authority.Register(4242, keyDigest, "conn-b"); err != nil {
		t.Fatalf("second register: %v", err)
	}
	if err := authority.UnregisterConnection(4242, "20260816T120000Z-4242"); err != nil {
		t.Fatalf("unregister connection: %v", err)
	}
	records, err = authority.Lookup("aaaaaaaaaaaaaaaa", "20260816T120000Z", enrollment.PublicKeyDigest(publicKey))
	if err != nil || len(records) != 1 {
		t.Fatalf("lookup after one unregister records=%d err=%v", len(records), err)
	}
	if err := authority.Unregister(4242); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	records, err = authority.Lookup("aaaaaaaaaaaaaaaa", "20260816T120000Z", enrollment.PublicKeyDigest(publicKey))
	if err != nil || len(records) != 0 {
		t.Fatalf("lookup after unregister records=%d err=%v", len(records), err)
	}
}

func TestClearMatchingRemovesLegacyPIDNamedRecords(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	record := Record{
		Kind:            Kind,
		SchemaVersion:   SchemaVersion,
		GrantID:         "bbbbbbbbbbbbbbbb",
		ClientID:        "aaaaaaaaaaaaaaaa",
		Generation:      "20260816T120000Z",
		PublicKeySHA256: strings.Repeat("a", 64),
		KeyBlobSHA256:   strings.Repeat("b", 64),
		BootID:          "boot-1",
		PID:             4242,
		StartTime:       "99",
		Exe:             "/opt/warptweet/bin/warptweet",
		ConnectionID:    "conn-legacy",
		RegisteredAt:    "2026-08-16T12:00:00Z",
	}
	legacy := filepath.Join(root, "aaaaaaaaaaaaaaaa-20260816T120000Z-4242.json")
	if err := writeRecord(legacy, record); err != nil {
		t.Fatal(err)
	}
	authority := &Authority{Root: root}
	if err := authority.Unregister(4242); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy PID-named record remained")
	}
}

func TestAuthorityClearDeletesUnparseableRecords(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "broken.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority := &Authority{Root: root}
	if err := authority.Clear("aaaaaaaaaaaaaaaa", "20260816T120000Z", strings.Repeat("a", 64)); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unparseable record remained")
	}
}

func TestMatchGrantSessionsIgnoresEmptyGeneration(t *testing.T) {
	t.Parallel()

	match := matchGrantSessions("aaaaaaaaaaaaaaaa", "", "")
	if !match(Record{ClientID: "aaaaaaaaaaaaaaaa", Generation: "old", PublicKeySHA256: strings.Repeat("a", 64)}) {
		t.Fatal("empty generation should match every generation for the client")
	}
	if match(Record{ClientID: "bbbbbbbbbbbbbbbb", Generation: "old", PublicKeySHA256: strings.Repeat("a", 64)}) {
		t.Fatal("matched a different client")
	}
	oldOnly := matchGrantSessions("aaaaaaaaaaaaaaaa", "old", "")
	if oldOnly(Record{ClientID: "aaaaaaaaaaaaaaaa", Generation: "new", PublicKeySHA256: strings.Repeat("a", 64)}) {
		t.Fatal("explicit generation should not match another generation")
	}
}

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	if _, err := decodeRequest([]byte(`{"version":1,"action":"register","key_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}`)); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestValidateRequestRejectsBadConnectionID(t *testing.T) {
	t.Parallel()

	key := strings.Repeat("a", 64)
	if err := ValidateRequest(Request{Version: 1, Action: ActionRegister, KeySHA256: key}); err != nil {
		t.Fatalf("empty connection: %v", err)
	}
	if err := ValidateRequest(Request{Version: 1, Action: ActionRegister, KeySHA256: key, Connection: "20260816T120000Z-4242"}); err != nil {
		t.Fatalf("generation-pid: %v", err)
	}
	if err := ValidateRequest(Request{Version: 1, Action: ActionRegister, KeySHA256: key, Connection: "bad id"}); err == nil {
		t.Fatal("accepted space in connection_id")
	}
	if err := ValidateRequest(Request{Version: 1, Action: ActionRegister, KeySHA256: key, Connection: strings.Repeat("a", maxConnectionIDBytes+1)}); err == nil {
		t.Fatal("accepted oversized connection_id")
	}
}
