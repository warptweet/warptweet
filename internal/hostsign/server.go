package hostsign

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/opensshkey"
)

// Serve loads the host private key and answers sign/public requests.
func Serve(ctx context.Context, listener net.Listener, keyPath string, allowUID int) error {
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	key, err := opensshkey.ParsePrivate(pem)
	if err != nil {
		return err
	}
	conns := &connTracker{m: map[net.Conn]struct{}{}}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		conns.closeAll()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		conns.add(conn)
		go func(conn net.Conn) {
			defer conns.remove(conn)
			serveConn(conn, key, allowUID)
		}(conn)
	}
}

type connTracker struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func (t *connTracker) add(conn net.Conn) {
	t.mu.Lock()
	t.m[conn] = struct{}{}
	t.mu.Unlock()
}

func (t *connTracker) remove(conn net.Conn) {
	t.mu.Lock()
	delete(t.m, conn)
	t.mu.Unlock()
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for conn := range t.m {
		_ = conn.Close()
		delete(t.m, conn)
	}
}

func serveConn(conn net.Conn, key composite.PrivateKey, allowUID int) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := authorizePeer(conn, allowUID); err != nil {
		_ = writeError(conn, err.Error())
		return
	}
	raw, err := readFrame(conn)
	if err != nil {
		return
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		_ = writeError(conn, "invalid request")
		return
	}
	if req.Version != ProtocolVersion {
		_ = writeError(conn, "unsupported version")
		return
	}
	resp := Response{Version: ProtocolVersion}
	switch req.Op {
	case OpPublic:
		pub, err := key.Public()
		if err != nil {
			_ = writeError(conn, err.Error())
			return
		}
		resp.Public = pub
	case OpSign:
		if len(req.Message) == 0 || len(req.Message) > 256 {
			_ = writeError(conn, "invalid message")
			return
		}
		sig, err := key.Sign(req.Message)
		if err != nil {
			_ = writeError(conn, err.Error())
			return
		}
		resp.Signature = sig
	default:
		_ = writeError(conn, fmt.Sprintf("unknown op %q", req.Op))
		return
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = writeFrame(conn, out)
}

func writeError(conn net.Conn, message string) error {
	out, err := json.Marshal(Response{Version: ProtocolVersion, Error: message})
	if err != nil {
		return err
	}
	return writeFrame(conn, out)
}
