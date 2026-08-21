package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/opensshkey"
)

const maxIdentificationBytes = 255

// Serve accepts SSH connections on policy.Listen and enforces the WarpTweet
// algorithm and channel contract. Only direct-tcpip to the pinned destinations
// is forwarded.
func Serve(ctx context.Context, policy Policy, stdout io.Writer) error {
	hostPEM, err := os.ReadFile(policy.HostKeyPath)
	if err != nil {
		return err
	}
	hostKey, err := opensshkey.ParsePrivate(hostPEM)
	if err != nil {
		return err
	}
	authRaw, err := os.ReadFile(policy.AuthorizedKeysPath)
	if err != nil {
		return err
	}
	clients, err := authorizedRawKeys(authRaw)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", policy.Listen.String())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", policy.Listen, err)
	}
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	closeTracked := func() {
		mu.Lock()
		defer mu.Unlock()
		for conn := range conns {
			_ = conn.Close()
		}
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		closeTracked()
	}()
	if stdout != nil {
		_, _ = fmt.Fprintf(stdout, "data plane listening\nlisten   %s\ntarget   %s\n", policy.Listen, policy.Target)
	}
	sessions := &sessionTable{}
	controlErr := make(chan error, 1)
	if policy.ControlSocket != "" {
		control, err := listenControl(policy.ControlSocket)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("control socket: %w", err)
		}
		done := ctx.Done()
		go func() {
			err := serveControl(done, control, sessions)
			if ctx.Err() != nil {
				controlErr <- nil
				return
			}
			controlErr <- err
			_ = listener.Close()
		}()
	}
	slots := make(chan struct{}, 64)
	for {
		conn, err := listener.Accept()
		if err != nil {
			closeTracked()
			if ctx.Err() != nil {
				return nil
			}
			select {
			case cerr := <-controlErr:
				if cerr != nil {
					return cerr
				}
			default:
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			closeTracked()
			return nil
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			_ = conn.Close()
			closeTracked()
			return nil
		}
		conns[conn] = struct{}{}
		mu.Unlock()
		go func(conn net.Conn) {
			defer func() {
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
				<-slots
			}()
			_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
			_ = serveConnection(conn, policy, hostKey, clients, sessions)
		}(conn)
	}
}

func writePacket(conn net.Conn, payload []byte) error {
	padding := 8 - ((1 + len(payload) + 4) % 8)
	if padding < 4 {
		padding += 8
	}
	packetLen := 1 + len(payload) + padding
	frame := make([]byte, 0, 4+packetLen)
	frame = binary.BigEndian.AppendUint32(frame, uint32(packetLen))
	frame = append(frame, byte(padding))
	frame = append(frame, payload...)
	start := len(frame)
	frame = append(frame, make([]byte, padding)...)
	if _, err := rand.Read(frame[start:]); err != nil {
		return err
	}
	_, err := conn.Write(frame)
	return err
}
