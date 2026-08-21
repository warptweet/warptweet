package opensshkey

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/sshwire"
)

const (
	authMagic = "openssh-key-v1\x00"
	pemType   = "OPENSSH PRIVATE KEY"
)

func appendString(dst, value []byte) []byte {
	return sshwire.AppendString(dst, value)
}

func consumeUint32(input []byte) ([]byte, uint32, error) {
	if len(input) < 4 {
		return nil, 0, errors.New("truncated OpenSSH uint32")
	}
	return input[4:], binary.BigEndian.Uint32(input[:4]), nil
}

// MarshalPrivate writes an unencrypted OpenSSH private key for the composite algorithm.
func MarshalPrivate(key composite.PrivateKey, comment string) ([]byte, error) {
	pub, err := key.Public()
	if err != nil {
		return nil, err
	}
	pubBlob := appendString(appendString(nil, []byte(composite.Algorithm)), pub)
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, err
	}
	priv := append(append([]byte{}, check[:]...), check[:]...)
	priv = appendString(priv, []byte(composite.Algorithm))
	priv = appendString(priv, pub)
	priv = appendString(priv, key.Secret())
	priv = appendString(priv, []byte(comment))
	for i := 1; len(priv)%8 != 0; i++ {
		priv = append(priv, byte(i))
	}
	body := append([]byte(authMagic), nil...)
	body = appendString(body, []byte("none"))
	body = appendString(body, []byte("none"))
	body = appendString(body, nil)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = appendString(body, pubBlob)
	body = appendString(body, priv)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: body}), nil
}

// ParsePrivate reads an unencrypted composite OpenSSH private key.
func ParsePrivate(pemBytes []byte) (composite.PrivateKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != pemType || len(bytes.TrimSpace(rest)) != 0 {
		return composite.PrivateKey{}, errors.New("not an OpenSSH private key")
	}
	body := block.Bytes
	if !bytes.HasPrefix(body, []byte(authMagic)) {
		return composite.PrivateKey{}, errors.New("missing openssh-key-v1 magic")
	}
	rest = body[len(authMagic):]
	rest, cipher, err := sshwire.ConsumeString(rest)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	rest, kdf, err := sshwire.ConsumeString(rest)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	if string(cipher) != "none" || string(kdf) != "none" {
		return composite.PrivateKey{}, errors.New("WarpTweet host keys must be unencrypted")
	}
	rest, _, err = sshwire.ConsumeString(rest)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	rest, nkeys, err := consumeUint32(rest)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	if nkeys != 1 {
		return composite.PrivateKey{}, fmt.Errorf("OpenSSH private key has %d keys, want 1", nkeys)
	}
	rest, outerPub, err := sshwire.ConsumeString(rest)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	rest, priv, err := sshwire.ConsumeString(rest)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	if len(rest) != 0 {
		return composite.PrivateKey{}, errors.New("trailing data after OpenSSH private key")
	}
	if len(priv) < 8 {
		return composite.PrivateKey{}, errors.New("truncated private key body")
	}
	if !bytes.Equal(priv[:4], priv[4:8]) {
		return composite.PrivateKey{}, errors.New("private key check integers mismatch")
	}
	priv = priv[8:]
	priv, alg, err := sshwire.ConsumeString(priv)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	if string(alg) != composite.Algorithm {
		return composite.PrivateKey{}, fmt.Errorf("host key algorithm %q", alg)
	}
	priv, pub, err := sshwire.ConsumeString(priv)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	priv, sk, err := sshwire.ConsumeString(priv)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	priv, _, err = sshwire.ConsumeString(priv)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	for i, b := range priv {
		if b != byte(i+1) {
			return composite.PrivateKey{}, errors.New("invalid OpenSSH private key padding")
		}
	}
	key, err := composite.NewPrivateKey(sk)
	if err != nil {
		return composite.PrivateKey{}, err
	}
	wantPub, err := key.Public()
	if err != nil {
		return composite.PrivateKey{}, err
	}
	if !bytes.Equal(wantPub, pub) {
		return composite.PrivateKey{}, errors.New("OpenSSH private key public mismatch")
	}
	wantOuter := appendString(appendString(nil, []byte(composite.Algorithm)), wantPub)
	if !bytes.Equal(outerPub, wantOuter) {
		return composite.PrivateKey{}, errors.New("OpenSSH private key outer public blob mismatch")
	}
	return key, nil
}
