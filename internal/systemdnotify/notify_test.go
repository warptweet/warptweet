package systemdnotify

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDisabledNotifierIsNoOp(t *testing.T) {
	t.Parallel()

	notifier, err := FromEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatalf("FromEnvironment: %v", err)
	}
	if notifier.Enabled() {
		t.Fatal("notifier unexpectedly enabled")
	}
	if err := notifier.Ready("authenticated tunnel ready"); err != nil {
		t.Fatalf("disabled Ready: %v", err)
	}
}

func TestReadySendsExactBoundedDatagram(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "notify.sock")
	notifier, err := FromEnvironment(func(name string) string {
		if name != "NOTIFY_SOCKET" {
			t.Fatalf("unexpected environment lookup %q", name)
		}
		return socketPath
	})
	if err != nil {
		t.Fatalf("FromEnvironment: %v", err)
	}
	if !notifier.Enabled() {
		t.Fatal("notifier unexpectedly disabled")
	}
	var sentSocket string
	var sentPayload string
	notifier.send = func(socket string, payload []byte) error {
		sentSocket = socket
		sentPayload = string(payload)
		return nil
	}
	if err := notifier.Ready("authenticated transport and local listener ready"); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if sentSocket != socketPath {
		t.Fatalf("notification socket = %q, want %q", sentSocket, socketPath)
	}
	want := "READY=1\nSTATUS=authenticated transport and local listener ready"
	if sentPayload != want {
		t.Fatalf("notification = %q, want %q", sentPayload, want)
	}
}

func TestNotifierRejectsUnsafeSocketAndStatus(t *testing.T) {
	t.Parallel()

	for _, socket := range []string{"relative.sock", "@", "bad\x00socket"} {
		if _, err := FromEnvironment(func(string) string { return socket }); err == nil {
			t.Fatalf("FromEnvironment accepted unsafe socket %q", socket)
		}
	}

	notifier := Notifier{socket: filepath.Join(t.TempDir(), "absent.sock")}
	for _, status := range []string{"", "injected\nREADY=1", strings.Repeat("a", maximumStatusBytes+1)} {
		if err := notifier.Ready(status); err == nil {
			t.Fatalf("Ready accepted unsafe status %q", status)
		}
	}
}
