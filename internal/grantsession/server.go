package grantsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// Server is the root-owned Unix-socket grant registrar.
type Server struct {
	Socket    string
	Authority *Authority
}

// Serve listens until the context is cancelled.
func (server *Server) Serve(ctx context.Context) error {
	if server.Socket == "" || server.Authority == nil {
		return fmt.Errorf("grant session server is incomplete")
	}
	if err := os.MkdirAll(dirOf(server.Socket), 0o755); err != nil {
		return err
	}
	if err := removeExistingGrantSocket(server.Socket); err != nil {
		return err
	}
	listener, err := net.Listen("unix", server.Socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(server.Socket, 0o600); err != nil {
		_ = listener.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go server.handle(connection)
	}
}

func (server *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	raw, err := readBounded(connection, MaxRequestBytes)
	if err != nil {
		_, _ = connection.Write(encodeResponse(Response{OK: false, Error: err.Error()}))
		return
	}
	request, err := decodeRequest(raw)
	if err != nil {
		_, _ = connection.Write(encodeResponse(Response{OK: false, Error: err.Error()}))
		return
	}
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		_, _ = connection.Write(encodeResponse(Response{OK: false, Error: "connection is not a Unix socket"}))
		return
	}
	pid, err := peerPID(unixConn)
	if err != nil {
		_, _ = connection.Write(encodeResponse(Response{OK: false, Error: err.Error()}))
		return
	}
	switch request.Action {
	case ActionRegister:
		if _, err := server.Authority.Register(pid, request.KeySHA256, request.Connection); err != nil {
			_, _ = connection.Write(encodeResponse(Response{OK: false, Error: err.Error()}))
			return
		}
	case ActionUnregister:
		if err := server.Authority.Unregister(pid); err != nil {
			_, _ = connection.Write(encodeResponse(Response{OK: false, Error: err.Error()}))
			return
		}
	}
	_, _ = connection.Write(encodeResponse(Response{OK: true}))
}

func removeExistingGrantSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("grant session path exists and is not a socket")
	}
	return os.Remove(path)
}

func dirOf(path string) string {
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

var _ syscall.Conn = (*net.UnixConn)(nil)
