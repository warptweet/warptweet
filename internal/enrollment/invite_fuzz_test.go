package enrollment

import (
	"testing"
	"time"
)

func FuzzParseClientInvite(f *testing.F) {
	f.Add([]byte(`{"kind":"warptweet.invite"}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _, _ = ParseClientInvite(raw, time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC))
	})
}
