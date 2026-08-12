//go:build linux

package systemdnotify

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestLinuxAbstractNotificationTransport(t *testing.T) {
	t.Parallel()

	abstractName := fmt.Sprintf("\x00warptweet-notify-%d-%d", os.Getpid(), time.Now().UnixNano())
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: abstractName, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen on abstract notification socket: %v", err)
	}
	defer listener.Close()

	notifier, err := FromEnvironment(func(string) string { return "@" + abstractName[1:] })
	if err != nil {
		t.Fatalf("FromEnvironment: %v", err)
	}
	if err := notifier.Ready("authenticated transport and local listener ready"); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set notification read deadline: %v", err)
	}
	buffer := make([]byte, 1024)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatalf("read notification: %v", err)
	}
	want := "READY=1\nSTATUS=authenticated transport and local listener ready"
	if got := string(buffer[:count]); got != want {
		t.Fatalf("notification = %q, want %q", got, want)
	}
}
