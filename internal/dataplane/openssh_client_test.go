package dataplane

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/engine"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/opensshkey"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestOpenSSHClientDirectTCPIP(t *testing.T) {
	sshPath, keygenPath := packagedOpenSSH(t)

	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "host")
	clientKeyPath := filepath.Join(dir, "client")
	generateOpenSSHKey(t, keygenPath, hostKeyPath, "dataplane-host")
	generateOpenSSHKey(t, keygenPath, clientKeyPath, "dataplane-client")

	hostPEM, err := os.ReadFile(hostKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opensshkey.ParsePrivate(hostPEM); err != nil {
		t.Fatalf("ParsePrivate rejected OpenSSH ssh-keygen host key: %v", err)
	}

	backend, backendAddr := startEchoBackend(t)
	defer backend.Close()

	listenAddr := freeAddrPort(t)
	localAddr := freeAddrPort(t)

	authPath := filepath.Join(dir, "authorized_keys")
	clientPub, err := os.ReadFile(clientKeyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authPath, clientPub, 0o600); err != nil {
		t.Fatal(err)
	}

	policy := mustPolicy(t)
	policy.Listen = listenAddr
	policy.Target = backendAddr
	policy.HostKeyPath = hostKeyPath
	policy.AuthorizedKeysPath = authPath

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, policy, nil)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	})
	waitForListen(t, errCh, policy.Listen.String())

	hostPub, err := os.ReadFile(hostKeyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	knownHosts, err := knownhosts.RenderManagedHost("loopback", hostPub)
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPath := filepath.Join(dir, "known_hosts")
	emptyKnownHosts := filepath.Join(dir, "known_hosts.empty")
	if err := os.WriteFile(knownHostsPath, knownHosts, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyKnownHosts, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatal(err)
	}
	args, err := engine.Arguments(engine.ClientSpec{
		TunnelID:             "loopback",
		ServerAddress:        listenAddr.Addr(),
		ServerPort:           listenAddr.Port(),
		ServerUser:           server.DefaultDedicatedUser,
		ListenAddress:        netip.MustParseAddr("127.0.0.1"),
		ListenPort:           localAddr.Port(),
		TargetAddress:        backendAddr.Addr(),
		TargetPort:           backendAddr.Port(),
		IdentityFile:         clientKeyPath,
		KnownHostsFile:       knownHostsPath,
		GlobalKnownHostsFile: emptyKnownHosts,
		Profile:              selected,
	})
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(sshPath, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	errOut := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(stderr)
		errOut <- out
	}()

	payload := []byte("openssh-dataplane")
	var conn net.Conn
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			t.Fatalf("ssh exited early: %s", <-errOut)
		}
		conn, err = net.DialTimeout("tcp", localAddr.String(), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		select {
		case out := <-errOut:
			t.Fatalf("dial LocalForward: %v\nssh stderr:\n%s", err, out)
		default:
			t.Fatalf("dial LocalForward: %v", err)
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		select {
		case out := <-errOut:
			t.Fatalf("echo read: %v\nssh stderr:\n%s", err, out)
		default:
			t.Fatalf("echo read: %v", err)
		}
	}
	if string(got) != string(payload) {
		t.Fatalf("echo=%q", got)
	}
}

func packagedOpenSSH(t *testing.T) (sshPath, keygenPath string) {
	t.Helper()
	candidates := [][2]string{
		{installlayout.DarwinSSHPath, installlayout.DarwinSSHKeygenPath},
		{installlayout.SSHPath, installlayout.SSHKeygenPath},
	}
	if prefix := os.Getenv("WARPTWEET_OPENSSH_PREFIX"); prefix != "" {
		candidates = append([][2]string{{
			filepath.Join(prefix, "bin", "ssh"),
			filepath.Join(prefix, "bin", "ssh-keygen"),
		}}, candidates...)
	}
	for _, pair := range candidates {
		if fileExists(pair[0]) && fileExists(pair[1]) {
			return pair[0], pair[1]
		}
	}
	t.Skip("packaged OpenSSH 10.4p1 is not installed")
	return "", ""
}

func generateOpenSSHKey(t *testing.T, keygenPath, destination, comment string) {
	t.Helper()
	cmd := exec.Command(keygenPath, "-q", "-t", "mldsa44-ed25519", "-N", "", "-C", comment, "-f", destination)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
}

func freeAddrPort(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		t.Fatal("listener address")
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port))
}

func waitForListen(t *testing.T, errCh <-chan error, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		select {
		case serveErr := <-errCh:
			t.Fatalf("Serve returned early: %v", serveErr)
		default:
		}
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("data plane listen: %v", err)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
