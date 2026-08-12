package sshwire

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

const testAlgorithm = "ssh-mldsa44-ed25519@openssh.com"

func TestValidatePublicKeyBlob(t *testing.T) {
	t.Parallel()

	encoded := testBlob(testAlgorithm, 1344, nil)
	if err := ValidatePublicKeyBlob(encoded, testAlgorithm, 1344); err != nil {
		t.Fatalf("ValidatePublicKeyBlob: %v", err)
	}
}

func TestValidatePublicKeyBlobRejectsConfusionAndLengthErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "wrong algorithm", encoded: testBlob("ssh-ed25519", 1344, nil)},
		{name: "short key", encoded: testBlob(testAlgorithm, 32, nil)},
		{name: "trailing bytes", encoded: testBlob(testAlgorithm, 1344, []byte{1})},
		{name: "invalid base64", encoded: "***"},
		{
			name: "noncanonical base64",
			encoded: withNoncanonicalPaddingBits(
				testBlob(testAlgorithm, 1343, nil),
			),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rawKeyBytes := 1344
			if test.name == "noncanonical base64" {
				rawKeyBytes = 1343
			}
			if err := ValidatePublicKeyBlob(test.encoded, testAlgorithm, rawKeyBytes); err == nil {
				t.Fatal("ValidatePublicKeyBlob accepted malformed input")
			}
		})
	}
}

func TestValidatePublicKeyBlobRejectsInvalidExpectedSize(t *testing.T) {
	t.Parallel()

	if err := ValidatePublicKeyBlob("", testAlgorithm, 0); err == nil {
		t.Fatal("ValidatePublicKeyBlob accepted a zero expected raw-key size")
	}
	if err := ValidatePublicKeyBlob("", testAlgorithm, -1); err == nil {
		t.Fatal("ValidatePublicKeyBlob accepted a negative expected raw-key size")
	}
}

func testBlob(algorithm string, rawSize int, trailing []byte) string {
	name := []byte(algorithm)
	blob := make([]byte, 4+len(name)+4+rawSize+len(trailing))
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(rawSize))
	copy(blob[offset+4+rawSize:], trailing)
	return base64.StdEncoding.EncodeToString(blob)
}

func withNoncanonicalPaddingBits(encoded string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if !strings.HasSuffix(encoded, "=") || strings.HasSuffix(encoded, "==") {
		panic("test encoding must have exactly one padding character")
	}
	index := len(encoded) - 2
	value := strings.IndexByte(alphabet, encoded[index])
	if value < 0 || value&0x03 != 0 {
		panic("test encoding has unexpected final symbol")
	}
	result := []byte(encoded)
	result[index] = alphabet[value|0x01]
	return string(result)
}
