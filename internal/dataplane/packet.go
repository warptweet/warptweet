package dataplane

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	maxPacket       = 256 << 10
	chachaKeySize   = 32
	chachaKeyTotal  = 64
	chachaNonceSize = 12
	poly1305TagSize = 16
	chachaBlock     = 8
)

type packetCodec interface {
	seal(seq uint64, payload []byte) ([]byte, error)
	open(seq uint64, r io.Reader) ([]byte, error)
}

type chachaDirection struct {
	payloadKey [chachaKeySize]byte
	lengthKey  [chachaKeySize]byte
}

func newChaChaDirection(key []byte) (*chachaDirection, error) {
	if len(key) < chachaKeyTotal {
		return nil, fmt.Errorf("chacha20-poly1305 key is %d bytes, want %d", len(key), chachaKeyTotal)
	}
	d := &chachaDirection{}
	copy(d.payloadKey[:], key[:chachaKeySize])
	copy(d.lengthKey[:], key[chachaKeySize:chachaKeyTotal])
	return d, nil
}

func seqNonce(seq uint64) [chachaNonceSize]byte {
	var n [chachaNonceSize]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

func (d *chachaDirection) seal(seq uint64, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty SSH payload")
	}
	body, err := padPayload(payload, chachaBlock)
	if err != nil {
		return nil, err
	}
	nonce := seqNonce(seq)
	encLen := make([]byte, 4)
	binary.BigEndian.PutUint32(encLen, uint32(len(body)))
	lengthStream, err := chacha20.NewUnauthenticatedCipher(d.lengthKey[:], nonce[:])
	if err != nil {
		return nil, err
	}
	lengthStream.XORKeyStream(encLen, encLen)
	encBody := make([]byte, len(body))
	payloadStream, err := chacha20.NewUnauthenticatedCipher(d.payloadKey[:], nonce[:])
	if err != nil {
		return nil, err
	}
	payloadStream.SetCounter(1)
	payloadStream.XORKeyStream(encBody, body)
	tag, err := poly1305Tag(d.payloadKey, nonce, encLen, encBody)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(encBody)+poly1305TagSize)
	out = append(out, encLen...)
	out = append(out, encBody...)
	return append(out, tag[:]...), nil
}

func (d *chachaDirection) open(seq uint64, r io.Reader) ([]byte, error) {
	encLen := make([]byte, 4)
	if _, err := io.ReadFull(r, encLen); err != nil {
		return nil, err
	}
	nonce := seqNonce(seq)
	plainLen := append([]byte(nil), encLen...)
	lengthStream, err := chacha20.NewUnauthenticatedCipher(d.lengthKey[:], nonce[:])
	if err != nil {
		return nil, err
	}
	lengthStream.XORKeyStream(plainLen, plainLen)
	n := binary.BigEndian.Uint32(plainLen)
	if n < 5 || n > maxPacket {
		return nil, fmt.Errorf("invalid packet length %d", n)
	}
	rest := make([]byte, int(n)+poly1305TagSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	encBody := rest[:n]
	got := rest[n:]
	want, err := poly1305Tag(d.payloadKey, nonce, encLen, encBody)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(got, want[:]) != 1 {
		return nil, fmt.Errorf("chacha20-poly1305 tag mismatch")
	}
	body := make([]byte, len(encBody))
	payloadStream, err := chacha20.NewUnauthenticatedCipher(d.payloadKey[:], nonce[:])
	if err != nil {
		return nil, err
	}
	payloadStream.SetCounter(1)
	payloadStream.XORKeyStream(body, encBody)
	return unpadPayload(body)
}

func poly1305Tag(payloadKey [chachaKeySize]byte, nonce [chachaNonceSize]byte, encLen, encBody []byte) ([poly1305TagSize]byte, error) {
	var tag [poly1305TagSize]byte
	stream, err := chacha20.NewUnauthenticatedCipher(payloadKey[:], nonce[:])
	if err != nil {
		return tag, err
	}
	var polyKey [32]byte
	stream.XORKeyStream(polyKey[:], polyKey[:])
	msg := make([]byte, 0, len(encLen)+len(encBody))
	msg = append(msg, encLen...)
	msg = append(msg, encBody...)
	poly1305.Sum(&tag, msg, &polyKey)
	return tag, nil
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
	if pad < 4 || 1+pad >= len(body) {
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
