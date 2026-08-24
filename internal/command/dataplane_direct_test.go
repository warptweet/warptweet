package command

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDirectDataPlaneRecognizesOwnListener(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcpAddr := listener.Addr().(*net.TCPAddr)
	endpoint := netip.AddrPortFrom(tcpAddr.AddrPort().Addr().Unmap(), uint16(tcpAddr.Port))
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "dataplane.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := ensureDirectDataPlane(context.Background(), stateDir, endpoint, false)
	if err != nil {
		t.Fatalf("own listener: %v", err)
	}
	if status != "direct_ready" {
		t.Fatalf("status=%s", status)
	}
}

func TestDirectDataPlaneRejectsForeignOccupancy(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcpAddr := listener.Addr().(*net.TCPAddr)
	endpoint := netip.AddrPortFrom(tcpAddr.AddrPort().Addr().Unmap(), uint16(tcpAddr.Port))
	_, err = ensureDirectDataPlane(context.Background(), t.TempDir(), endpoint, false)
	if err == nil || !strings.Contains(err.Error(), "occupied outside") {
		t.Fatalf("error=%v", err)
	}
}
