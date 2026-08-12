package opensslsource

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedOpenSSLSourceConstants(t *testing.T) {
	t.Parallel()

	if Version != "3.5.7" || Archive != "openssl-"+Version+".tar.gz" {
		t.Fatalf("inconsistent OpenSSL version/archive: %q %q", Version, Archive)
	}
	if SignatureURL != SourceURL+".asc" {
		t.Fatalf("signature URL = %q, want archive URL plus .asc", SignatureURL)
	}
	if !strings.HasPrefix(SourceURL, "https://github.com/openssl/openssl/releases/download/") ||
		ReleaseKeyURL != "https://openssl-library.org/source/pubkeys.asc" {
		t.Fatal("OpenSSL provenance must use official HTTPS release locations")
	}
	if decoded, err := hex.DecodeString(SourceSHA256); err != nil || len(decoded) != sha256.Size {
		t.Fatalf("invalid source SHA-256 %q: %v", SourceSHA256, err)
	}
	if decoded, err := hex.DecodeString(ReleaseKeyFingerprint); err != nil || len(decoded) != 20 {
		t.Fatalf("invalid signing fingerprint %q: %v", ReleaseKeyFingerprint, err)
	}
	for _, path := range []string{LogicalPrefix, LogicalConfigDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatalf("logical path %q is not clean and absolute", path)
		}
	}
}
