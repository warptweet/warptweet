package dataplane

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/opensshkey"
)

func TestServeExchangesIdentification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := opensshkey.MarshalPrivate(key, "host")
	if err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(dir, "host")
	if err := os.WriteFile(hostPath, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(dir, "authorized_keys")
	writeTestAuthorizedKey(t, authPath)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()

	policy := mustPolicy(t)
	addr, _ := netip.AddrFromSlice(tcpAddr.IP)
	policy.Listen = netip.AddrPortFrom(addr.Unmap(), uint16(tcpAddr.Port))
	policy.HostKeyPath = hostPath
	policy.AuthorizedKeysPath = authPath

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, policy, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	var conn net.Conn
	for time.Now().Before(deadline) {
		select {
		case serveErr := <-errCh:
			t.Fatalf("Serve returned early: %v", serveErr)
		default:
		}
		conn, err = net.DialTimeout("tcp", policy.Listen.String(), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("SSH-2.0-TestClient\r\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	ident, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if ident != policy.identification()+"\r\n" {
		t.Fatalf("ident=%q", ident)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestIgnoreDuringInitialKEXDisconnects(t *testing.T) {
	t.Parallel()

	server := startLoopbackServer(t)
	conn, err := net.DialTimeout("tcp", server.policy.Listen.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("SSH-2.0-TestClient\r\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	kex, err := readClearPacket(reader)
	if err != nil || len(kex) == 0 || kex[0] != sshMsgKexInit {
		t.Fatalf("expected server KEXINIT, got %v %v", msgType(kex), err)
	}
	if err := writePacket(conn, []byte{sshMsgIgnore}); err != nil {
		t.Fatal(err)
	}
	payload, err := readClearPacket(reader)
	switch {
	case err == nil:
		if len(payload) == 0 || payload[0] != sshMsgDisconnect {
			t.Fatalf("server accepted IGNORE during initial KEX: %v", msgType(payload))
		}
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatal("server neither disconnected nor closed after IGNORE during initial KEX")
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
	default:
		t.Fatalf("unexpected read after IGNORE: %v", err)
	}
}

func TestPreflightRejectsMissingAndWorldWritableKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policy := mustPolicy(t)
	policy.AuthorizedKeysPath = filepath.Join(dir, "missing")
	policy.HostKeyPath = filepath.Join(dir, "host")
	if err := Preflight(policy); err == nil {
		t.Fatal("accepted missing authorized_keys")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	policy.AuthorizedKeysPath = empty
	if err := os.WriteFile(policy.HostKeyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(policy); err != nil {
		t.Fatalf("empty authorized_keys before first enroll: %v", err)
	}
	auth := filepath.Join(dir, "authorized_keys")
	writeTestAuthorizedKey(t, auth)
	if err := os.Chmod(auth, 0o666); err != nil {
		t.Fatal(err)
	}
	policy.AuthorizedKeysPath = auth
	if err := os.WriteFile(policy.HostKeyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(policy); err == nil {
		t.Fatal("accepted world-writable authorized_keys")
	}
	if err := os.Chmod(auth, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(auth, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(policy); err == nil {
		t.Fatal("accepted group-writable authorized_keys")
	}
	if err := os.Chmod(auth, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(policy); err != nil {
		t.Fatal(err)
	}
}

func TestKnownClientConsultsLiveAuthorizedKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	authPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	c := &connection{policy: Policy{AuthorizedKeysPath: authPath}}
	if c.knownClient(rawPub) {
		t.Fatal("empty authorized_keys accepted a client key")
	}
	line := composite.Algorithm + " " + base64.StdEncoding.EncodeToString(hostKeyBlob(rawPub)) + "\n"
	if err := os.WriteFile(authPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.knownClient(rawPub) {
		t.Fatal("live authorized_keys did not accept the enrolled key")
	}
}

func writeTestAuthorizedKey(t *testing.T, path string) {
	t.Helper()
	key, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	line := composite.Algorithm + " " + base64.StdEncoding.EncodeToString(hostKeyBlob(rawPub)) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}
