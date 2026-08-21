package composite

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCompositeSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	var sk [SecretKeySize]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatal(err)
	}
	key, err := NewPrivateKey(sk[:])
	if err != nil {
		t.Fatal(err)
	}
	pk, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != PublicKeySize {
		t.Fatalf("pk=%d", len(pk))
	}
	msg := []byte("WarpTweet exchange hash")
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pk, msg, sig); err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	if err := Verify(pk, msg, sig); err == nil {
		t.Fatal("accepted mutated signature")
	}
	sig[0] ^= 1
	sig[len(sig)-1] ^= 1
	if err := Verify(pk, msg, sig); err == nil {
		t.Fatal("accepted mutated Ed25519 signature")
	}
	sig[len(sig)-1] ^= 1
	other, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := other.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(otherPub, msg, sig); err == nil {
		t.Fatal("accepted signature under a different public key")
	}
	if bytes.Equal(pk, make([]byte, len(pk))) {
		t.Fatal("public key is all zeros")
	}
}
