// Package sshwire validates the minimal public SSH encodings that cross
// WarpTweet's enrollment boundary. It does not implement cryptography.
package sshwire

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// ValidatePublicKeyBlob verifies the outer SSH key type, exact raw key size,
// and absence of trailing bytes in an authorized_keys or known_hosts blob.
func ValidatePublicKeyBlob(encoded, algorithm string, rawKeyBytes int) error {
	if rawKeyBytes <= 0 {
		return errors.New("expected raw public-key size must be positive")
	}
	expectedBlobBytes := 4 + len(algorithm) + 4 + rawKeyBytes
	expectedEncodedBytes := base64.StdEncoding.EncodedLen(expectedBlobBytes)
	if len(encoded) != expectedEncodedBytes {
		return fmt.Errorf(
			"public-key encoding is %d bytes, want %d",
			len(encoded),
			expectedEncodedBytes,
		)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("public key is not valid base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(blob) != encoded {
		return errors.New("public key is not canonical base64")
	}
	remaining, name, err := consumeString(blob)
	if err != nil {
		return fmt.Errorf("read public-key algorithm: %w", err)
	}
	if string(name) != algorithm {
		return fmt.Errorf("public-key blob type %q does not match %q", name, algorithm)
	}
	remaining, rawKey, err := consumeString(remaining)
	if err != nil {
		return fmt.Errorf("read raw public key: %w", err)
	}
	if len(rawKey) != rawKeyBytes {
		return fmt.Errorf("raw public key is %d bytes, want %d", len(rawKey), rawKeyBytes)
	}
	if len(remaining) != 0 {
		return fmt.Errorf("public-key blob contains %d trailing bytes", len(remaining))
	}
	return nil
}

func consumeString(input []byte) ([]byte, []byte, error) {
	if len(input) < 4 {
		return nil, nil, errors.New("truncated SSH string length")
	}
	length := binary.BigEndian.Uint32(input[:4])
	if uint64(length) > uint64(len(input)-4) {
		return nil, nil, errors.New("truncated SSH string value")
	}
	end := 4 + int(length)
	return input[end:], input[4:end], nil
}
