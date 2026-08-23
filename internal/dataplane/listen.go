package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/hostsign"
	"warptweet.com/warptweet/internal/opensshkey"
)

const maxIdentificationBytes = 255

// Serve accepts SSH connections on policy.Listen and enforces the WarpTweet
// algorithm and channel contract. Only direct-tcpip to the pinned destinations
// is forwarded.
func Serve(ctx context.Context, policy Policy, stdout io.Writer) error {
	if err := Preflight(policy); err != nil {
		return err
	}
	signer, err := loadHostSigner(policy)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", policy.Listen.String())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", policy.Listen, err)
	}
	return serveListener(ctx, listener, policy, stdout, signer)
}

// Preflight fails closed before the data plane opens a listener.
func Preflight(policy Policy) error {
	if policy.AuthorizedKeysPath == "" {
		return fmt.Errorf("authorized_keys path is required")
	}
	info, err := os.Stat(policy.AuthorizedKeysPath)
	if err != nil {
		return fmt.Errorf("authorized_keys: %w", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("authorized_keys is group-writable or world-writable")
	}
	authRaw, err := os.ReadFile(policy.AuthorizedKeysPath)
	if err != nil {
		return err
	}
	if _, err := authorizedRawKeys(authRaw); err != nil {
		return fmt.Errorf("authorized_keys: %w", err)
	}
	if policy.HostSignSocket != "" {
		if _, err := os.Stat(policy.HostSignSocket); err != nil {
			return fmt.Errorf("host sign socket: %w", err)
		}
		return nil
	}
	if policy.HostKeyPath == "" {
		return fmt.Errorf("host key path is required")
	}
	if _, err := os.Stat(policy.HostKeyPath); err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	return nil
}

func loadHostSigner(policy Policy) (HostSigner, error) {
	if policy.HostSignSocket != "" {
		return hostsign.Client{Path: policy.HostSignSocket}, nil
	}
	hostPEM, err := os.ReadFile(policy.HostKeyPath)
	if err != nil {
		return nil, err
	}
	return opensshkey.ParsePrivate(hostPEM)
}

func serveListener(ctx context.Context, listener net.Listener, policy Policy, stdout io.Writer, hostKey HostSigner) error {
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
	sources := &sourceLimiter{limit: policy.maxConnsPerSource()}
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
		source := connSource(conn)
		if !sources.acquire(source) {
			slog.Info("dataplane_reject", "reason", "source_quota", "source", source)
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			sources.release(source)
			_ = conn.Close()
			closeTracked()
			return nil
		default:
			sources.release(source)
			slog.Info("dataplane_reject", "reason", "connection_slots_full")
			_ = conn.Close()
			continue
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			sources.release(source)
			_ = conn.Close()
			closeTracked()
			return nil
		}
		conns[conn] = struct{}{}
		mu.Unlock()
		go func(conn net.Conn, source string) {
			defer func() {
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
				sources.release(source)
				<-slots
			}()
			_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
			_ = serveConnection(ctx, conn, policy, hostKey, sessions)
		}(conn, source)
	}
}

type sourceLimiter struct {
	mu    sync.Mutex
	n     map[string]int
	limit int
}

func (s *sourceLimiter) acquire(source string) bool {
	if s.limit <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == nil {
		s.n = map[string]int{}
	}
	if s.n[source] >= s.limit {
		return false
	}
	s.n[source]++
	return true
}

func (s *sourceLimiter) release(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == nil {
		return
	}
	s.n[source]--
	if s.n[source] <= 0 {
		delete(s.n, source)
	}
}

func connSource(conn net.Conn) string {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return conn.RemoteAddr().String()
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return ip.Unmap().String()
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
