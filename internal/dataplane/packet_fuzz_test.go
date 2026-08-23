package dataplane

import (
	"bytes"
	"testing"
)

func FuzzReadClearPacket(f *testing.F) {
	f.Add([]byte{0, 0, 0, 8, 4, 20, 1, 2, 3, 4, 5, 6})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = readClearPacket(bytes.NewReader(raw))
	})
}
