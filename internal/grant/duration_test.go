package grant

import (
	"strings"
	"testing"
	"time"
)

func TestParseAccessDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    time.Duration
		wantErr string
	}{
		{in: "30d", want: 30 * 24 * time.Hour},
		{in: "24h", want: 24 * time.Hour},
		{in: "15m", want: 15 * time.Minute},
		{in: "30s", want: 30 * time.Second},
		{in: "1d", want: 24 * time.Hour},
		{in: " 7d ", want: 7 * 24 * time.Hour},
		{in: "", wantErr: "empty"},
		{in: "30", wantErr: "unit"},
		{in: "30.5d", wantErr: "fractional"},
		{in: "-30d", wantErr: "positive"},
		{in: "0d", wantErr: "positive"},
		{in: "30days", wantErr: "unit"},
		{in: "1d12h", wantErr: "unit"},
		{in: "30e2s", wantErr: "fractional"},
		{in: "999999999999d", wantErr: "overflows"},
	}
	for _, testCase := range cases {
		t.Run(testCase.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAccessDuration(testCase.in)
			if testCase.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
					t.Errorf("ParseAccessDuration(%q) err=%v, want %q", testCase.in, err, testCase.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseAccessDuration(%q): %v", testCase.in, err)
				return
			}
			if got != testCase.want {
				t.Errorf("ParseAccessDuration(%q)=%s, want %s", testCase.in, got, testCase.want)
			}
		})
	}
}

func TestSecondsRejectsFractionalAndZero(t *testing.T) {
	t.Parallel()

	if _, err := Seconds(0); err == nil {
		t.Fatal("Seconds accepted zero")
	}
	if _, err := Seconds(-time.Second); err == nil {
		t.Fatal("Seconds accepted negative")
	}
	if _, err := Seconds(1500 * time.Millisecond); err == nil {
		t.Fatal("Seconds accepted fractional second")
	}
	got, err := Seconds(30 * 24 * time.Hour)
	if err != nil || got != 2592000 {
		t.Fatalf("Seconds(30d)=%d %v", got, err)
	}
}

func TestAuthorizationNotAfterExact(t *testing.T) {
	t.Parallel()

	accepted := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	notAfter, encoded, err := AuthorizationNotAfter(accepted, 2592000)
	if err != nil {
		t.Fatalf("AuthorizationNotAfter: %v", err)
	}
	want := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	if !notAfter.Equal(want) {
		t.Fatalf("notAfter=%s want %s", notAfter, want)
	}
	parsed, err := ParseUTC(encoded)
	if err != nil || !parsed.Equal(want) {
		t.Fatalf("encoded=%q parsed=%s err=%v", encoded, parsed, err)
	}
}

func TestOpenSSHExpiryTimeUTC(t *testing.T) {
	t.Parallel()

	notAfter := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got, err := OpenSSHExpiryTime(notAfter)
	if err != nil {
		t.Fatalf("OpenSSHExpiryTime: %v", err)
	}
	if got != "20260915120000Z" {
		t.Fatalf("expiry-time=%q", got)
	}
}
