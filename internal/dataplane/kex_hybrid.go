package dataplane

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	mlkemPublicKeyBytes  = mlkem.EncapsulationKeySize768
	mlkemCiphertextBytes = mlkem.CiphertextSize768
	x25519Size           = 32
	mlkemSharedBytes     = mlkem.SharedKeySize
)

func serverHybridEncapsulate(clientBlob []byte) (serverBlob, sharedSecret []byte, err error) {
	need := mlkemPublicKeyBytes + x25519Size
	if len(clientBlob) != need {
		return nil, nil, fmt.Errorf("client KEX blob is %d bytes, want %d", len(clientBlob), need)
	}
	ek, err := mlkem.NewEncapsulationKey768(clientBlob[:mlkemPublicKeyBytes])
	if err != nil {
		return nil, nil, err
	}
	kemSecret, ciphertext := ek.Encapsulate()
	if len(ciphertext) != mlkemCiphertextBytes || len(kemSecret) != mlkemSharedBytes {
		return nil, nil, errors.New("unexpected ML-KEM-768 encapsulate sizes")
	}
	serverX, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	clientX, err := ecdh.X25519().NewPublicKey(clientBlob[mlkemPublicKeyBytes:])
	if err != nil {
		return nil, nil, err
	}
	ecdhSecret, err := serverX.ECDH(clientX)
	if err != nil {
		return nil, nil, err
	}
	if isZero(ecdhSecret) {
		return nil, nil, errors.New("X25519 shared secret is all zeros")
	}
	serverBlob = make([]byte, 0, mlkemCiphertextBytes+x25519Size)
	serverBlob = append(serverBlob, ciphertext...)
	serverBlob = append(serverBlob, serverX.PublicKey().Bytes()...)
	concat := append(append([]byte{}, kemSecret...), ecdhSecret...)
	sum := sha256.Sum256(concat)
	sharedSecret = sum[:]
	return serverBlob, sharedSecret, nil
}

func clientHybridDecapsulate(clientMLKEM *mlkem.DecapsulationKey768, clientX *ecdh.PrivateKey, serverBlob []byte) ([]byte, error) {
	need := mlkemCiphertextBytes + x25519Size
	if len(serverBlob) != need {
		return nil, fmt.Errorf("server KEX blob is %d bytes, want %d", len(serverBlob), need)
	}
	kemSecret, err := clientMLKEM.Decapsulate(serverBlob[:mlkemCiphertextBytes])
	if err != nil {
		return nil, err
	}
	serverX, err := ecdh.X25519().NewPublicKey(serverBlob[mlkemCiphertextBytes:])
	if err != nil {
		return nil, err
	}
	ecdhSecret, err := clientX.ECDH(serverX)
	if err != nil {
		return nil, err
	}
	if isZero(ecdhSecret) {
		return nil, errors.New("X25519 shared secret is all zeros")
	}
	concat := append(append([]byte{}, kemSecret...), ecdhSecret...)
	sum := sha256.Sum256(concat)
	return sum[:], nil
}

func isZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}
