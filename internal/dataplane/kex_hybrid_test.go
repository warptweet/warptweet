package dataplane

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"testing"
)

func TestHybridKEXAgreesOnSharedSecret(t *testing.T) {
	t.Parallel()

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	clientX, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientBlob := append(append([]byte{}, dk.EncapsulationKey().Bytes()...), clientX.PublicKey().Bytes()...)
	serverBlob, serverSecret, err := serverHybridEncapsulate(clientBlob)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret, err := clientHybridDecapsulate(dk, clientX, serverBlob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serverSecret, clientSecret) {
		t.Fatal("hybrid KEX shared secrets diverged")
	}
	if len(serverSecret) != 32 {
		t.Fatalf("shared secret is %d bytes", len(serverSecret))
	}
}

func TestHybridKEXRejectsMalformedBlobs(t *testing.T) {
	t.Parallel()

	if _, _, err := serverHybridEncapsulate(nil); err == nil {
		t.Fatal("accepted empty client blob")
	}
	if _, _, err := serverHybridEncapsulate(make([]byte, mlkemPublicKeyBytes+x25519Size+1)); err == nil {
		t.Fatal("accepted over-long client blob")
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	clientX, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientHybridDecapsulate(dk, clientX, nil); err == nil {
		t.Fatal("accepted empty server blob")
	}
	if _, err := clientHybridDecapsulate(dk, clientX, make([]byte, mlkemCiphertextBytes+x25519Size+1)); err == nil {
		t.Fatal("accepted over-long server blob")
	}
	clientBlob := append(append([]byte{}, dk.EncapsulationKey().Bytes()...), clientX.PublicKey().Bytes()...)
	serverBlob, serverSecret, err := serverHybridEncapsulate(clientBlob)
	if err != nil {
		t.Fatal(err)
	}
	serverBlob[0] ^= 0xff
	clientSecret, err := clientHybridDecapsulate(dk, clientX, serverBlob)
	if err == nil && bytes.Equal(clientSecret, serverSecret) {
		t.Fatal("corrupted ciphertext agreed with server secret")
	}
}
