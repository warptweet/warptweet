package dataplane

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/grantsession"
)

type sessionTable struct {
	mu sync.Mutex
	m  map[string]*connection
}

func (table *sessionTable) track(c *connection) {
	if table == nil || c == nil || c.connectionID == "" {
		return
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.m == nil {
		table.m = map[string]*connection{}
	}
	table.m[c.connectionID] = c
}

func (table *sessionTable) untrack(id string) {
	if table == nil || id == "" {
		return
	}
	table.mu.Lock()
	delete(table.m, id)
	table.mu.Unlock()
}

func (table *sessionTable) dropKey(digest string) {
	if table == nil || digest == "" {
		return
	}
	table.mu.Lock()
	var conns []*connection
	for _, c := range table.m {
		if c.keyDigest == digest {
			conns = append(conns, c)
		}
	}
	table.mu.Unlock()
	for _, c := range conns {
		_ = c.conn.Close()
	}
}

func listenControl(path string) (net.Listener, error) {
	if err := os.MkdirAll(dirOfPath(path), 0o750); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func serveControl(ctxDone <-chan struct{}, listener net.Listener, sessions *sessionTable) error {
	go func() {
		<-ctxDone
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctxDone:
				return nil
			default:
				return err
			}
		}
		go handleControl(conn, sessions)
	}
}

func handleControl(conn net.Conn, sessions *sessionTable) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var request grantsession.Request
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		_, _ = conn.Write(grantsession.EncodeError(err.Error()))
		return
	}
	if err := grantsession.ValidateRequest(request); err != nil {
		_, _ = conn.Write(grantsession.EncodeError(err.Error()))
		return
	}
	if request.Action != grantsession.ActionDrop {
		_, _ = conn.Write(grantsession.EncodeError("unsupported action"))
		return
	}
	sessions.dropKey(request.KeySHA256)
	_, _ = conn.Write(grantsession.EncodeOK())
}

func dirOfPath(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
