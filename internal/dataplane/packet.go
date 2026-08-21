package dataplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	maxPacket     = 256 << 10
	gcmTagSize    = 16
	gcmNonceSize  = 12
	aesGCMKeySize = 32
)

type gcmDirection struct {
	aead cipher.AEAD
	iv   [gcmNonceSize]byte
	seq  uint32
}

func newGCMDirection(key, iv []byte) (*gcmDirection, error) {
	if len(key) < aesGCMKeySize || len(iv) < gcmNonceSize {
		return nil, fmt.Errorf("AES-256-GCM key/iv too short")
	}
	block, err := aes.NewCipher(key[:aesGCMKeySize])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	d := &gcmDirection{aead: aead}
	copy(d.iv[:], iv[:gcmNonceSize])
	return d, nil
}

func (d *gcmDirection) seal(payload []byte) ([]byte, error) {
	body, err := padPayload(payload, 16)
	if err != nil {
		return nil, err
	}
	aad := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	nonce := d.iv
	ct := d.aead.Seal(nil, nonce[:], body, aad)
	incrementIV(&d.iv)
	d.seq++
	out := append(aad, ct...)
	return out, nil
}

func (d *gcmDirection) open(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 5 || n > maxPacket {
		return nil, fmt.Errorf("invalid packet length %d", n)
	}
	ct := make([]byte, n+gcmTagSize)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, err
	}
	nonce := d.iv
	body, err := d.aead.Open(nil, nonce[:], ct, lenBuf[:])
	if err != nil {
		return nil, err
	}
	incrementIV(&d.iv)
	d.seq++
	return unpadPayload(body)
}

func incrementIV(iv *[12]byte) {
	for i := 11; i >= 4; i-- {
		iv[i]++
		if iv[i] != 0 {
			return
		}
	}
}

func padPayload(payload []byte, block int) ([]byte, error) {
	padding := block - ((1 + len(payload)) % block)
	if padding < 4 {
		padding += block
	}
	out := make([]byte, 1+len(payload)+padding)
	out[0] = byte(padding)
	copy(out[1:], payload)
	if _, err := rand.Read(out[1+len(payload):]); err != nil {
		return nil, err
	}
	return out, nil
}

func unpadPayload(body []byte) ([]byte, error) {
	if len(body) < 5 {
		return nil, fmt.Errorf("short packet body")
	}
	pad := int(body[0])
	if pad < 4 || 1+pad > len(body) {
		return nil, fmt.Errorf("invalid padding %d", pad)
	}
	return body[1 : len(body)-pad], nil
}

func readClearPacket(r io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:4])
	if n < 12 || n > maxPacket {
		return nil, fmt.Errorf("invalid clear packet length %d", n)
	}
	rest := make([]byte, n-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	pad := int(header[4])
	if pad < 4 || pad > len(rest) {
		return nil, fmt.Errorf("invalid clear padding")
	}
	return rest[:len(rest)-pad], nil
}
