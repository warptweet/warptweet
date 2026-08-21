package opensshkey

import (
	"bytes"
	"encoding/pem"
	"testing"

	"warptweet.com/warptweet/internal/composite"
)

func TestOpenSSHPrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := MarshalPrivate(key, "warptweet-host")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParsePrivate(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := loaded.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPub, wantPub) {
		t.Fatal("public key mismatch after OpenSSH round trip")
	}
	msg := []byte("exchange-hash")
	sig, err := loaded.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := composite.Verify(wantPub, msg, sig); err != nil {
		t.Fatal(err)
	}
}

func TestParsePrivateRejectsMalformedKeys(t *testing.T) {
	t.Parallel()

	key, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	good, err := MarshalPrivate(key, "warptweet-host")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(good)
	if block == nil {
		t.Fatal("marshal did not produce PEM")
	}
	const noneCipherFieldLen = 8
	if len(block.Bytes) < len(authMagic)+noneCipherFieldLen {
		t.Fatal("marshaled key missing cipher field")
	}
	encrypted := append([]byte(authMagic), nil...)
	encrypted = appendString(encrypted, []byte("aes256-ctr"))
	encrypted = append(encrypted, block.Bytes[len(authMagic)+noneCipherFieldLen:]...)

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "non-PEM", input: []byte("not-a-key")},
		{name: "wrong PEM type", input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block.Bytes})},
		{name: "trailing data", input: append(append([]byte(nil), good...), '\n', 'x')},
		{name: "missing magic", input: pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: []byte("nope")})},
		{name: "encrypted", input: pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: encrypted})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParsePrivate(test.input); err == nil {
				t.Fatal("accepted malformed key")
			}
		})
	}

	t.Run("nkeys", func(t *testing.T) {
		t.Parallel()
		body := append([]byte(authMagic), nil...)
		body = appendString(body, []byte("none"))
		body = appendString(body, []byte("none"))
		body = appendString(body, nil)
		body = append(body, 0, 0, 0, 2)
		body = appendString(body, []byte("x"))
		body = appendString(body, []byte("y"))
		if _, err := ParsePrivate(pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: body})); err == nil {
			t.Fatal("accepted nkeys!=1")
		}
	})
}
