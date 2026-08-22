package dataplane

import (
	"bytes"
	"testing"
)

func TestChaCha20RoundTrip(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x11}, chachaKeyTotal)
	w, err := newChaChaDirection(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newChaChaDirection(key)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{sshMsgNewKeys}
	frame, err := w.seal(3, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.open(3, bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %x", got)
	}
}

func TestChaCha20RejectsTamperedTag(t *testing.T) {
	t.Parallel()

	frame := mustSeal(t, 3, []byte{sshMsgIgnore, 0, 0, 0, 0})
	frame[len(frame)-1] ^= 0xff
	if _, err := mustReader(t).open(3, bytes.NewReader(frame)); err == nil {
		t.Fatal("accepted tampered tag")
	}
}

func TestChaCha20RejectsWrongSequenceNumber(t *testing.T) {
	t.Parallel()

	frame := mustSeal(t, 3, []byte{sshMsgIgnore, 0, 0, 0, 0})
	if _, err := mustReader(t).open(0, bytes.NewReader(frame)); err == nil {
		t.Fatal("accepted packet under sequence 0")
	}
	if _, err := mustReader(t).open(4, bytes.NewReader(frame)); err == nil {
		t.Fatal("accepted packet under sequence 4")
	}
}

func TestChaCha20RejectsFlippedLength(t *testing.T) {
	t.Parallel()

	frame := mustSeal(t, 3, []byte{sshMsgIgnore, 0, 0, 0, 0})
	frame[0] ^= 0xff
	if _, err := mustReader(t).open(3, bytes.NewReader(frame)); err == nil {
		t.Fatal("accepted flipped length")
	}
}

func TestChaCha20RejectsShortKey(t *testing.T) {
	t.Parallel()

	if _, err := newChaChaDirection(bytes.Repeat([]byte{0x33}, 32)); err == nil {
		t.Fatal("accepted 32-byte key")
	}
	if _, err := newChaChaDirection(nil); err == nil {
		t.Fatal("accepted empty key")
	}
}

func TestChaCha20RejectsWrongKey(t *testing.T) {
	t.Parallel()

	frame := mustSeal(t, 3, []byte{sshMsgUserauthSuccess})
	other, err := newChaChaDirection(bytes.Repeat([]byte{0x44}, chachaKeyTotal))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.open(3, bytes.NewReader(frame)); err == nil {
		t.Fatal("accepted packet under a different key")
	}
}

func TestChaCha20RejectsTruncatedFrame(t *testing.T) {
	t.Parallel()

	frame := mustSeal(t, 3, []byte{sshMsgIgnore, 0, 0, 0, 0})
	if _, err := mustReader(t).open(3, bytes.NewReader(frame[:3])); err == nil {
		t.Fatal("accepted truncated header")
	}
	if _, err := mustReader(t).open(3, bytes.NewReader(frame[:len(frame)-1])); err == nil {
		t.Fatal("accepted truncated tag")
	}
}

func TestChaCha20RejectsEmptyPayload(t *testing.T) {
	t.Parallel()

	w, err := newChaChaDirection(bytes.Repeat([]byte{0x55}, chachaKeyTotal))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.seal(0, nil); err == nil {
		t.Fatal("sealed empty payload")
	}
}

func TestUnpadRejectsPaddingThatLeavesNoMessage(t *testing.T) {
	t.Parallel()

	body := []byte{7, 1, 2, 3, 4, 5, 6, 7}
	if _, err := unpadPayload(body); err == nil {
		t.Fatal("accepted padding that consumes the message type")
	}
}

func TestWriteAndReadRejectWrappedSequence(t *testing.T) {
	t.Parallel()

	c := &connection{clearOut: true, clearIn: true, outSeq: maxSSHSeq + 1, inSeq: maxSSHSeq + 1}
	if err := c.write([]byte{sshMsgIgnore}); err == nil {
		t.Fatal("wrote after sequence wrap")
	}
	if _, err := c.read(); err == nil {
		t.Fatal("read after sequence wrap")
	}
}

func TestCheckSSHSeqBoundary(t *testing.T) {
	t.Parallel()

	if err := checkSSHSeq(maxSSHSeq); err != nil {
		t.Fatal(err)
	}
	if err := checkSSHSeq(maxSSHSeq + 1); err == nil {
		t.Fatal("accepted wrapped sequence")
	}
}

func mustSeal(t *testing.T, seq uint64, payload []byte) []byte {
	t.Helper()
	w, err := newChaChaDirection(bytes.Repeat([]byte{0x22}, chachaKeyTotal))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := w.seal(seq, payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func mustReader(t *testing.T) *chachaDirection {
	t.Helper()
	r, err := newChaChaDirection(bytes.Repeat([]byte{0x22}, chachaKeyTotal))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
