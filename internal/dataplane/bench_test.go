package dataplane

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"io"
	"net"
	"testing"
	"time"
)

func BenchmarkChaCha20Seal(b *testing.B) {
	key := bytes.Repeat([]byte{0x11}, chachaKeyTotal)
	w, err := newChaChaDirection(key)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x61}, 1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.seal(uint64(i), payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Open(b *testing.B) {
	key := bytes.Repeat([]byte{0x11}, chachaKeyTotal)
	w, err := newChaChaDirection(key)
	if err != nil {
		b.Fatal(err)
	}
	r, err := newChaChaDirection(key)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x61}, 1024)
	frame, err := w.seal(0, payload)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.open(0, bytes.NewReader(frame)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHybridKEX(b *testing.B) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		b.Fatal(err)
	}
	clientX, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	clientBlob := append(append([]byte{}, dk.EncapsulationKey().Bytes()...), clientX.PublicKey().Bytes()...)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serverBlob, _, err := serverHybridEncapsulate(clientBlob)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := clientHybridDecapsulate(dk, clientX, serverBlob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoopbackHandshake(b *testing.B) {
	server := startLoopbackServer(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client := server.dial(b)
		_ = client.conn.Close()
	}
}

func BenchmarkLoopbackRTT(b *testing.B) {
	client, policy := startAuthenticatedLoopback(b)
	remoteID, localID, err := client.openDirectTCPIP(policy.Target)
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte{0x79}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := client.sendData(remoteID, payload); err != nil {
			b.Fatal(err)
		}
		if _, err := client.recvExact(localID, remoteID, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoopbackForward1KiB(b *testing.B) {
	benchmarkLoopbackForward(b, 1024)
}

func BenchmarkLoopbackForward64KiB(b *testing.B) {
	benchmarkLoopbackForward(b, 64<<10)
}

func BenchmarkRawTCPForward64KiB(b *testing.B) {
	_, backend := startEchoBackend(b)
	conn, err := net.DialTimeout("tcp", backend.String(), time.Second)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	payload := bytes.Repeat([]byte{0x63}, 64<<10)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkLoopbackForward(b *testing.B, size int) {
	b.Helper()
	client, policy := startAuthenticatedLoopback(b)
	remoteID, localID, err := client.openDirectTCPIP(policy.Target)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x62}, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.conn.SetDeadline(time.Now().Add(30 * time.Second))
		if err := client.sendData(remoteID, payload); err != nil {
			b.Fatal(err)
		}
		got, err := client.recvExact(localID, remoteID, size)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != size {
			b.Fatalf("got %d bytes", len(got))
		}
	}
}
