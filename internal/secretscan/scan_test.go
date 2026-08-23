package secretscan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanTreeFailsOnPlantedInviteAndKey(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	invite := []byte(`{
  "kind": "warptweet.invite",
  "nonce": "0123456789abcdef0123456789abcdef",
  "mac": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}
`)
	if err := os.WriteFile(filepath.Join(root, "invite.json"), invite, 0o600); err != nil {
		t.Fatal(err)
	}
	key := []byte("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END " + "OPENSSH PRIVATE KEY-----\n")
	if err := os.WriteFile(filepath.Join(root, "id_ed25519"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	var sawInvite, sawKey bool
	for _, finding := range findings {
		switch {
		case finding.Reason == "invite mac and nonce":
			sawInvite = true
		case strings.Contains(finding.Reason, "private key"):
			sawKey = true
		}
	}
	if !sawInvite || !sawKey {
		t.Fatalf("planted material not detected: %+v", findings)
	}
}

func TestScanTreeDetectsEncryptedPKCS8(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	key := []byte("-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END " + "ENCRYPTED PRIVATE KEY-----\n")
	if err := os.WriteFile(filepath.Join(root, "client-identity.txt"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Reason, "private key") {
		t.Fatalf("encrypted PKCS#8 not detected: %+v", findings)
	}
}

func TestScanTreeSkipsGitignoredWorkspaces(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	work := filepath.Join(root, "scripts", "interop", "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	invite := []byte(`{"kind":"warptweet.invite","nonce":"0123456789abcdef0123456789abcdef","mac":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`)
	if err := os.WriteFile(filepath.Join(work, "local.wtinvite"), invite, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("gitignored workspace findings: %+v", findings)
	}
}

func TestRepositoryHasNoSecretMaterial(t *testing.T) {
	t.Parallel()

	findings, err := ScanTree(repositoryRoot(t))
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("secret-pattern findings: %+v", findings)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
