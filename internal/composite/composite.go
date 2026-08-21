package composite

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"warptweet.com/warptweet/internal/mldsa"
)

const (
	Algorithm = "ssh-mldsa44-ed25519@openssh.com"

	prefix = "CompositeAlgorithmSignatures2025"
	label  = "COMPSIG-MLDSA44-Ed25519-SHA512"

	PublicKeySize  = mldsa.PublicKeySize44 + ed25519.PublicKeySize
	SecretKeySize  = 32 + ed25519.SeedSize
	SignatureSize  = mldsa.SignatureSize44 + 64
	MLDSAPublicLen = mldsa.PublicKeySize44
)

// PrivateKey is mldsaSeed || ed25519Seed.
type PrivateKey struct {
	mldsaSeed   [32]byte
	ed25519Seed [32]byte
}

func Generate() (PrivateKey, error) {
	var sk [SecretKeySize]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return PrivateKey{}, err
	}
	return NewPrivateKey(sk[:])
}

func NewPrivateKey(sk []byte) (PrivateKey, error) {
	if len(sk) != SecretKeySize {
		return PrivateKey{}, fmt.Errorf("composite secret key is %d bytes, want %d", len(sk), SecretKeySize)
	}
	var key PrivateKey
	copy(key.mldsaSeed[:], sk[:32])
	copy(key.ed25519Seed[:], sk[32:])
	return key, nil
}

func (key PrivateKey) Seed() []byte {
	out := make([]byte, 32)
	copy(out, key.mldsaSeed[:])
	return out
}

func (key PrivateKey) Ed25519Seed() []byte {
	out := make([]byte, 32)
	copy(out, key.ed25519Seed[:])
	return out
}

func (key PrivateKey) Secret() []byte {
	out := make([]byte, SecretKeySize)
	copy(out[:32], key.mldsaSeed[:])
	copy(out[32:], key.ed25519Seed[:])
	return out
}

func (key PrivateKey) Public() ([]byte, error) {
	mldsaKey, err := mldsa.NewPrivateKey44(key.mldsaSeed[:])
	if err != nil {
		return nil, err
	}
	edPub := ed25519.NewKeyFromSeed(key.ed25519Seed[:]).Public().(ed25519.PublicKey)
	out := make([]byte, PublicKeySize)
	copy(out, mldsaKey.PublicKey().Bytes())
	copy(out[MLDSAPublicLen:], edPub)
	return out, nil
}

func (key PrivateKey) Sign(msg []byte) ([]byte, error) {
	mPrime := constructMPrime(msg)
	mldsaKey, err := mldsa.NewPrivateKey44(key.mldsaSeed[:])
	if err != nil {
		return nil, err
	}
	mldsaSig, err := mldsa.Sign(mldsaKey, mPrime, label)
	if err != nil {
		return nil, err
	}
	if len(mldsaSig) != mldsa.SignatureSize44 {
		return nil, errors.New("unexpected ML-DSA-44 signature size")
	}
	edKey := ed25519.NewKeyFromSeed(key.ed25519Seed[:])
	edSig := ed25519.Sign(edKey, mPrime)
	out := make([]byte, SignatureSize)
	copy(out, mldsaSig)
	copy(out[mldsa.SignatureSize44:], edSig)
	return out, nil
}

func Verify(pk, msg, sig []byte) error {
	if len(pk) != PublicKeySize {
		return fmt.Errorf("composite public key is %d bytes, want %d", len(pk), PublicKeySize)
	}
	if len(sig) != SignatureSize {
		return fmt.Errorf("composite signature is %d bytes, want %d", len(sig), SignatureSize)
	}
	mldsaPub, err := mldsa.NewPublicKey44(pk[:MLDSAPublicLen])
	if err != nil {
		return err
	}
	mPrime := constructMPrime(msg)
	if err := mldsa.Verify(mldsaPub, mPrime, sig[:mldsa.SignatureSize44], label); err != nil {
		return fmt.Errorf("ML-DSA-44 verify: %w", err)
	}
	edPub := ed25519.PublicKey(pk[MLDSAPublicLen:])
	if !ed25519.Verify(edPub, mPrime, sig[mldsa.SignatureSize44:]) {
		return errors.New("Ed25519 verify failed")
	}
	return nil
}

func constructMPrime(msg []byte) []byte {
	sum := sha512.Sum512(msg)
	out := make([]byte, 0, len(prefix)+len(label)+1+len(sum))
	out = append(out, prefix...)
	out = append(out, label...)
	out = append(out, 0)
	out = append(out, sum[:]...)
	return out
}
