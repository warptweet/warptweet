package mldsa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMLDSA44DeterministicKAT(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0x42}, 32)
	priv, err := NewPrivateKey44(seed)
	if err != nil {
		t.Fatal(err)
	}
	pk := priv.PublicKey().Bytes()
	if len(pk) != PublicKeySize44 {
		t.Fatalf("pk=%d, want %d", len(pk), PublicKeySize44)
	}
	sig, err := SignDeterministic(priv, []byte("warptweet"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize44 {
		t.Fatalf("sig=%d, want %d", len(sig), SignatureSize44)
	}
	if got := sha256Hex(pk); got != "19506c63f504c175013cf1b459397bbbc2ce6a3fd841bab68b3898f6f2fddc2f" {
		t.Fatalf("pk sha256=%s", got)
	}
	if got := sha256Hex(sig); got != "1235c47777aa3fd6b24b7ac18b90b6c1e6e0deaaf202d83b694e5de07d27893a" {
		t.Fatalf("sig sha256=%s", got)
	}
	if err := Verify(priv.PublicKey(), []byte("warptweet"), sig, ""); err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	if err := Verify(priv.PublicKey(), []byte("warptweet"), sig, ""); err == nil {
		t.Fatal("accepted mutated signature")
	}
}

func TestNewPublicKey44RejectsMalformed(t *testing.T) {
	t.Parallel()

	if _, err := NewPublicKey44(nil); err == nil {
		t.Fatal("accepted empty public key")
	}
	if _, err := NewPublicKey44(bytes.Repeat([]byte{0xff}, PublicKeySize44-1)); err == nil {
		t.Fatal("accepted short public key")
	}
	if _, err := NewPrivateKey44(bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Fatal("accepted short seed")
	}
}

func TestSOURCERecordsGo1264Provenance(t *testing.T) {
	t.Parallel()

	raw, err := testdataSOURCE(t)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("Go 1.26.4")) {
		t.Fatal("SOURCE missing Go 1.26.4")
	}
	if !bytes.Contains(raw, []byte("487e8d6c474f16989d8617b60591aa6a908ee58bbce45ca2c3108db83a2a9924")) {
		t.Fatal("SOURCE missing upstream hash")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	sum := sha256.New()
	for _, name := range []string{"field.go", "mldsa.go", "semiexpanded.go"} {
		contents, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = sum.Write([]byte(name))
		_, _ = sum.Write(contents)
	}
	want := hex.EncodeToString(sum.Sum(nil))
	if !bytes.Contains(raw, []byte("This tree SHA-256: "+want)) {
		t.Fatalf("SOURCE tree hash does not match adapted sources, want %s", want)
	}
}

func testdataSOURCE(t *testing.T) ([]byte, error) {
	t.Helper()
	return readSOURCE()
}

func sha256Hex(in []byte) string {
	sum := sha256.Sum256(in)
	return hex.EncodeToString(sum[:])
}
