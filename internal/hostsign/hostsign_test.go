package hostsign

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/opensshkey"
)

func TestSignAndPublicOverUnixSocket(t *testing.T) {
	t.Parallel()

	key, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "host")
	pem, err := opensshkey.MarshalPrivate(key, "host")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join("/tmp", "wths-test.sock")
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, listener, keyPath, -1)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(time.Second):
		}
	})

	client := Client{Path: sock}
	gotPub, err := client.Public()
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPub) != string(wantPub) {
		t.Fatal("public key mismatch")
	}
	msg := []byte("hostsign-test-message")
	sig, err := client.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := composite.Verify(gotPub, msg, sig); err != nil {
		t.Fatal(err)
	}
}
