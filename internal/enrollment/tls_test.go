package enrollment

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnrollmentTLSIdentityPinsExactHybridTLS(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "tls.crt")
	keyPath := filepath.Join(directory, "tls.key")
	pin, created, renewed, err := EnsureTLSIdentity(certPath, keyPath, now)
	if err != nil || !created || !renewed {
		t.Fatalf("EnsureTLSIdentity: pin=%q created=%v renewed=%v err=%v", pin, created, renewed, err)
	}
	samePin, createdAgain, renewedAgain, err := EnsureTLSIdentity(certPath, keyPath, now.Add(time.Hour))
	if err != nil || createdAgain || renewedAgain || samePin != pin {
		t.Fatalf("identity was not stable: pin=%q created=%v renewed=%v err=%v", samePin, createdAgain, renewedAgain, err)
	}
	serverConfig, err := LoadServerTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := PinnedClientTLSConfig(pin, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 ||
		len(serverConfig.CurvePreferences) != 1 || serverConfig.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("server TLS profile drifted: %+v", serverConfig)
	}
	leaf, err := loadEnrollmentLeaf(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: EnrollmentALPN,
		PeerCertificates:   []*x509.Certificate{leaf},
	}
	if err := clientConfig.VerifyConnection(state); err != nil {
		t.Fatalf("pinned TLS verification: %v", err)
	}
	assertEmptySAN(t, leaf)
	wrongConfig, err := PinnedClientTLSConfig(strings.Repeat("f", 64), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongConfig.VerifyConnection(state); err == nil || !strings.Contains(err.Error(), "SPKI pin mismatch") {
		t.Fatalf("wrong pin was not rejected: %v", err)
	}
}

func TestEnrollmentTLSRenewalPreservesSPKI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "tls.crt")
	keyPath := filepath.Join(directory, "tls.key")
	first, _, _, err := EnsureTLSIdentity(certPath, keyPath, now)
	if err != nil {
		t.Fatal(err)
	}
	beforeLeaf, err := loadEnrollmentLeaf(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, created, renewed, err := EnsureTLSIdentity(certPath, keyPath, now.Add(EnrollmentCertificateLifetime-EnrollmentCertificateRenewBefore/2))
	if err != nil || created || !renewed || second != first {
		t.Fatalf("renewal changed identity: first=%q second=%q created=%v renewed=%v err=%v", first, second, created, renewed, err)
	}
	afterLeaf, err := loadEnrollmentLeaf(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !afterLeaf.NotAfter.After(beforeLeaf.NotAfter) {
		t.Fatalf("renewal did not extend validity: before=%s after=%s", beforeLeaf.NotAfter, afterLeaf.NotAfter)
	}
	assertEmptySAN(t, beforeLeaf)
	assertEmptySAN(t, afterLeaf)
}

func TestEnrollmentTLSCertificatesHaveEmptySAN(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "tls.crt")
	keyPath := filepath.Join(directory, "tls.key")
	if _, _, _, err := EnsureTLSIdentity(certPath, keyPath, now); err != nil {
		t.Fatal(err)
	}
	leaf, err := loadEnrollmentLeaf(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	assertEmptySAN(t, leaf)
	if _, created, renewed, err := EnsureTLSIdentity(certPath, keyPath, now.Add(time.Hour)); err != nil || created || renewed {
		t.Fatalf("locator-independent call renewed: created=%v renewed=%v err=%v", created, renewed, err)
	}
	same, err := loadEnrollmentLeaf(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if same.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("stable identity rewrote the certificate")
	}
	assertEmptySAN(t, same)
}

func assertEmptySAN(t *testing.T, leaf *x509.Certificate) {
	t.Helper()
	if len(leaf.IPAddresses) != 0 || len(leaf.DNSNames) != 0 {
		t.Fatalf("enrollment certificate has SAN IPAddresses=%v DNSNames=%v", leaf.IPAddresses, leaf.DNSNames)
	}
}

func TestEnsureTLSIdentityConcurrentProcesses(t *testing.T) {
	if os.Getenv("WT_ENROLLMENT_TLS_WORKER") == "1" {
		certPath := os.Getenv("WT_ENROLLMENT_TLS_CERT")
		keyPath := os.Getenv("WT_ENROLLMENT_TLS_KEY")
		pin, _, _, err := EnsureTLSIdentity(certPath, keyPath, time.Now().UTC())
		if err != nil {
			t.Fatalf("worker EnsureTLSIdentity: %v", err)
		}
		if _, err := os.Stdout.WriteString(pin + "\n"); err != nil {
			t.Fatalf("write pin: %v", err)
		}
		return
	}

	t.Parallel()

	directory := t.TempDir()
	certPath := filepath.Join(directory, "tls.crt")
	keyPath := filepath.Join(directory, "tls.key")
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	const workers = 8
	var waitGroup sync.WaitGroup
	errors := make(chan error, workers)
	pins := make(chan string, workers)
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			command := exec.Command(exe, "-test.run=^TestEnsureTLSIdentityConcurrentProcesses$", "-test.v=false", "-test.count=1")
			command.Env = append(os.Environ(),
				"WT_ENROLLMENT_TLS_WORKER=1",
				"WT_ENROLLMENT_TLS_CERT="+certPath,
				"WT_ENROLLMENT_TLS_KEY="+keyPath,
			)
			output, runErr := command.CombinedOutput()
			if runErr != nil {
				errors <- fmt.Errorf("worker failed: %w (%s)", runErr, strings.TrimSpace(string(output)))
				return
			}
			pin := strings.TrimSpace(string(output))
			// go test may wrap worker output; keep the last non-empty line.
			lines := strings.Split(pin, "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				line := strings.TrimSpace(lines[i])
				if line != "" && isLowerHexDigest(line) {
					pins <- line
					return
				}
			}
			errors <- fmt.Errorf("worker produced no pin: %q", string(output))
		}()
	}
	waitGroup.Wait()
	close(errors)
	close(pins)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	var sharedPin string
	for pin := range pins {
		if sharedPin == "" {
			sharedPin = pin
			continue
		}
		if pin != sharedPin {
			t.Fatalf("workers disagreed on pin: %q vs %q", sharedPin, pin)
		}
	}
	if sharedPin == "" {
		t.Fatal("no worker pins collected")
	}

	leaf, err := loadEnrollmentLeaf(certPath, keyPath)
	if err != nil {
		t.Fatalf("loadEnrollmentLeaf: %v", err)
	}
	leafPin, err := SPKISHA256(leaf.PublicKey)
	if err != nil {
		t.Fatalf("SPKISHA256 leaf: %v", err)
	}
	if leafPin != sharedPin {
		t.Fatalf("persisted certificate pin=%q, want worker pin %q", leafPin, sharedPin)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	block, rest := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("persisted private key is not canonical PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("persisted private key is not Ed25519")
	}
	keyPin, err := SPKISHA256(privateKey.Public())
	if err != nil {
		t.Fatalf("SPKISHA256 key: %v", err)
	}
	if keyPin != sharedPin || keyPin != leafPin {
		t.Fatalf("key/cert/pin mismatch: key=%q cert=%q workers=%q", keyPin, leafPin, sharedPin)
	}
	if _, err := tls.X509KeyPair(mustRead(t, certPath), keyBytes); err != nil {
		t.Fatalf("certificate does not match private key: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
