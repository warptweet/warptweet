package command

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLimitedListenerCloseUnblocksSaturatedAccept(t *testing.T) {
	t.Parallel()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newLimitedListener(inner, 1)
	firstReady := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			firstReady <- nil
			return
		}
		firstReady <- conn
	}()
	client, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var first net.Conn
	select {
	case first = <-firstReady:
		if first == nil {
			t.Fatal("first Accept failed")
		}
	case <-time.After(time.Second):
		t.Fatal("first Accept did not complete")
	}
	defer first.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("saturated Accept returned nil after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("saturated Accept stayed blocked after Close")
	}
}

func TestLimitedListenerShutdownReturnsWhileSaturated(t *testing.T) {
	t.Parallel()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newLimitedListener(inner, enrollmentAcceptLimit)
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	held := make([]net.Conn, 0, enrollmentAcceptLimit)
	dialer := net.Dialer{Timeout: time.Second}
	for i := 0; i < enrollmentAcceptLimit; i++ {
		conn, err := dialer.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, conn)
	}
	t.Cleanup(func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Shutdown(ctx)
	}()
	for _, conn := range held {
		_ = conn.Close()
	}
	held = nil
	if err := <-errCh; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("Shutdown took %s", time.Since(started))
	}
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}
