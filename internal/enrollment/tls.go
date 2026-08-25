package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/locator"
)

const (
	// EnrollmentALPN pins the HTTP application protocol actually used by the
	// enrollment API. A private ALPN token cannot be carried by net/http as
	// HTTP/1.1; protocol separation instead comes from the dedicated pinned
	// enrollment identity, endpoint, paths, and strict request contracts.
	EnrollmentALPN = "http/1.1"
	// EnrollmentCertificateLifetime bounds one self-signed enrollment certificate.
	// Renewal reuses the same Ed25519 key, so existing SPKI pins remain valid.
	EnrollmentCertificateLifetime = 397 * 24 * time.Hour
	// EnrollmentCertificateRenewBefore renews while the pinned key is still valid.
	EnrollmentCertificateRenewBefore = 30 * 24 * time.Hour
)

// EnsureTLSIdentity creates or renews the pinned enrollment TLS identity.
// The private key never changes during renewal, preserving existing invite and
// management-receipt SPKI pins. keyCreated is true only when the private key was
// newly generated. renewed is true when a certificate was written.
// The full identity transaction is serialized with one cross-process lock over
// the shared key and certificate paths.
func EnsureTLSIdentity(certPath, keyPath string, now time.Time) (pin string, keyCreated bool, renewed bool, err error) {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return "", false, false, errors.New("enrollment TLS certificate and key paths are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	unlock, err := lockPathExclusive(
		filepath.Dir(keyPath),
		enrollmentTLSIdentityLockName(keyPath, certPath),
		"enrollment TLS identity",
		false,
	)
	if err != nil {
		return "", false, false, err
	}
	defer unlock()
	return ensureTLSIdentityLocked(certPath, keyPath, now)
}

func enrollmentTLSIdentityLockName(keyPath, certPath string) string {
	return "." + filepath.Base(keyPath) + "." + filepath.Base(certPath) + ".lock"
}

func ensureTLSIdentityLocked(certPath, keyPath string, now time.Time) (pin string, keyCreated bool, renewed bool, err error) {
	privateKey, keyCreated, err := loadOrCreateEnrollmentKey(keyPath)
	if err != nil {
		return "", false, false, err
	}
	pin, err = SPKISHA256(privateKey.Public())
	if err != nil {
		return "", false, false, err
	}

	renew := keyCreated
	if !renew {
		certificate, certErr := loadEnrollmentLeaf(certPath, keyPath)
		switch {
		case certErr == nil:
			certPin, pinErr := SPKISHA256(certificate.PublicKey)
			if pinErr != nil {
				return "", false, false, pinErr
			}
			if certPin != pin {
				return "", false, false, errors.New("enrollment TLS certificate does not match private key")
			}
			renew = !now.Before(certificate.NotAfter.Add(-EnrollmentCertificateRenewBefore))
		case os.IsNotExist(certErr):
			renew = true
		default:
			return "", false, false, certErr
		}
	}
	if !renew {
		return pin, false, false, nil
	}
	if err := writeEnrollmentCertificate(certPath, privateKey, now); err != nil {
		return "", false, false, err
	}
	return pin, keyCreated, true, nil
}

// LoadServerTLSConfig returns the exact fail-closed enrollment TLS profile.
func LoadServerTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load enrollment TLS identity: %w", err)
	}
	if len(certificate.Certificate) != 1 {
		return nil, errors.New("enrollment TLS identity must contain exactly one certificate")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse enrollment TLS certificate: %w", err)
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("enrollment TLS certificate must use Ed25519")
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		Certificates:     []tls.Certificate{certificate},
		NextProtos:       []string{EnrollmentALPN},
	}, nil
}

// PinnedClientTLSConfig authenticates the exact invite-pinned SPKI and exact
// hybrid TLS profile. InsecureSkipVerify is required only because the identity
// is self-signed; VerifyConnection performs the complete custom verification.
func PinnedClientTLSConfig(expectedSPKI string, now func() time.Time) (*tls.Config, error) {
	if !isLowerHexDigest(expectedSPKI) {
		return nil, fmt.Errorf("%w: enrollment TLS SPKI pin is invalid", ErrInvalidInvite)
	}
	if now == nil {
		now = time.Now
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:         []string{EnrollmentALPN},
		InsecureSkipVerify: true, // verified below against the invite pin
		VerifyConnection: func(state tls.ConnectionState) error {
			tlsErr := func(message string, err error) error {
				if err == nil {
					return locator.Classified(locator.ClassTLSNegotiate, "tls_negotiate", errors.New(message))
				}
				return locator.Classified(locator.ClassTLSNegotiate, "tls_negotiate", fmt.Errorf("%s: %w", message, err))
			}
			if state.Version != tls.VersionTLS13 {
				return tlsErr("enrollment TLS did not negotiate TLS 1.3", nil)
			}
			if state.NegotiatedProtocol != EnrollmentALPN {
				return tlsErr("enrollment TLS ALPN mismatch", nil)
			}
			if len(state.PeerCertificates) != 1 {
				return tlsErr("enrollment TLS peer must present exactly one certificate", nil)
			}
			certificate := state.PeerCertificates[0]
			if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok {
				return tlsErr("enrollment TLS peer certificate must use Ed25519", nil)
			}
			if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
				return tlsErr("enrollment TLS certificate is not self-signed", err)
			}
			current := now().UTC()
			if current.Before(certificate.NotBefore) || current.After(certificate.NotAfter) {
				return tlsErr("enrollment TLS certificate is outside its validity period", nil)
			}
			actual, err := SPKISHA256(certificate.PublicKey)
			if err != nil {
				return tlsErr("enrollment TLS SPKI", err)
			}
			if actual != expectedSPKI {
				return locator.Classified(locator.ClassTLSSPKI, "tls_spki", errors.New("enrollment TLS SPKI pin mismatch"))
			}
			return nil
		},
	}, nil
}

// SPKISHA256 returns lowercase SHA-256 of DER SubjectPublicKeyInfo.
func SPKISHA256(publicKey any) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal enrollment TLS SPKI: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func loadOrCreateEnrollmentKey(path string) (ed25519.PrivateKey, bool, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
			return nil, false, errors.New("enrollment TLS private key is not canonical PKCS#8 PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("parse enrollment TLS private key: %w", err)
		}
		privateKey, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, false, errors.New("enrollment TLS private key must use Ed25519")
		}
		return privateKey, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate enrollment TLS key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, false, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		return nil, false, err
	}
	return privateKey, true, nil
}

func writeEnrollmentCertificate(path string, privateKey ed25519.PrivateKey, now time.Time) error {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate enrollment TLS certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "WarpTweet enrollment"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(EnrollmentCertificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           nil,
		DNSNames:              nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return fmt.Errorf("create enrollment TLS certificate: %w", err)
	}
	return writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func loadEnrollmentLeaf(certPath, keyPath string) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) != 1 {
		return nil, errors.New("enrollment TLS identity must contain exactly one certificate")
	}
	return x509.ParseCertificate(pair.Certificate[0])
}
