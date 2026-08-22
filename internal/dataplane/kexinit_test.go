package dataplane

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestKexInitAdvertisesOnlyThePinnedProfile(t *testing.T) {
	t.Parallel()

	policy := mustPolicy(t)
	payload, err := policy.marshalKexInit()
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != sshMsgKexInit {
		t.Fatalf("msg=%d", payload[0])
	}
	rest := payload[17:]
	kex, rest := mustNameList(t, rest)
	hostKey, rest := mustNameList(t, rest)
	c2s, rest := mustNameList(t, rest)
	s2c, _ := mustNameList(t, rest)
	if kex != policy.Profile.KeyExchangeAlgorithm {
		t.Fatalf("kex=%q", kex)
	}
	if hostKey != policy.Profile.AuthenticationKeyType {
		t.Fatalf("hostkey=%q", hostKey)
	}
	if c2s != s2c || !strings.Contains(c2s, "chacha20-poly1305@openssh.com") || strings.Contains(c2s, "aes256-gcm@openssh.com") {
		t.Fatalf("ciphers c2s=%q s2c=%q", c2s, s2c)
	}
	if strings.Contains(kex, ",") || strings.Contains(hostKey, ",") {
		t.Fatal("KEXINIT advertised more than one KEX or host key algorithm")
	}
}

func TestClientOffersPinnedAlgorithmsRejectsAESOnly(t *testing.T) {
	t.Parallel()

	policy := mustPolicy(t)
	kex := fakeClientKexInit(t, policy.Profile.KeyExchangeAlgorithm, policy.Profile.AuthenticationKeyType, "aes256-gcm@openssh.com")
	if err := clientOffersPinnedAlgorithms(kex, policy); err == nil {
		t.Fatal("accepted AES-GCM-only client KEXINIT")
	}
}

func TestClientOffersPinnedAlgorithmsAcceptsChaCha20(t *testing.T) {
	t.Parallel()

	policy := mustPolicy(t)
	kex := fakeClientKexInit(t, policy.Profile.KeyExchangeAlgorithm, policy.Profile.AuthenticationKeyType, "chacha20-poly1305@openssh.com")
	if err := clientOffersPinnedAlgorithms(kex, policy); err != nil {
		t.Fatal(err)
	}
}

func fakeClientKexInit(t *testing.T, kex, hostKey, cipher string) []byte {
	t.Helper()
	payload := []byte{sshMsgKexInit}
	payload = append(payload, make([]byte, 16)...)
	payload = appendNameList(payload, kex)
	payload = appendNameList(payload, hostKey)
	payload = appendNameList(payload, cipher)
	payload = appendNameList(payload, cipher)
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "")
	payload = appendNameList(payload, "")
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint32(payload, 0)
	return payload
}

func mustNameList(t *testing.T, input []byte) (string, []byte) {
	t.Helper()
	if len(input) < 4 {
		t.Fatal("truncated name-list")
	}
	n := binary.BigEndian.Uint32(input[:4])
	if uint64(n) > uint64(len(input)-4) {
		t.Fatal("name-list overruns buffer")
	}
	return string(input[4 : 4+n]), input[4+n:]
}
