package locator

import (
	"errors"
	"testing"
)

func TestClientErrorClassesAreFrozen(t *testing.T) {
	t.Parallel()

	got := ClientErrorClasses()
	want := []string{
		ClassDNSResolution,
		ClassTCPConnect,
		ClassTLSNegotiate,
		ClassTLSSPKI,
		ClassInviteAuthorization,
		ClassSSHHostKey,
		ClassForwardTarget,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestErrorClassClassifiesClientFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err   error
		class string
	}{
		{err: Classified(ClassDNSResolution, "dns_resolution", errors.New("no such host")), class: ClassDNSResolution},
		{err: errors.New("enrollment TLS SPKI pin mismatch"), class: ClassTLSSPKI},
		{err: errors.New("tls: handshake failure"), class: ClassTLSNegotiate},
		{err: errors.New("Host key verification failed."), class: ClassSSHHostKey},
		{err: errors.New("channel open failed: administratively prohibited"), class: ClassForwardTarget},
		{err: errors.New("connect failed to 127.0.0.1 port 5432"), class: ClassForwardTarget},
		{err: errors.New("enrollment rejected: forbidden"), class: ClassInviteAuthorization},
		{err: errors.New("connection refused"), class: ClassTCPConnect},
	}
	for _, test := range tests {
		if got := ErrorClass(test.err); got != test.class {
			t.Errorf("ErrorClass(%q)=%q want %q", test.err, got, test.class)
		}
	}
}
