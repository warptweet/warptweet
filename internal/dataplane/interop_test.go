package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/opensshkey"
	"warptweet.com/warptweet/internal/server"
)

func TestLoopbackDirectTCPIP(t *testing.T) {
	t.Parallel()

	client, policy := startAuthenticatedLoopback(t)
	defer client.conn.Close()
	remoteID, localID, err := client.openDirectTCPIP(policy.Target)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("warptweet-loopback")
	if err := client.sendData(remoteID, payload); err != nil {
		t.Fatal(err)
	}
	got, err := client.recvData(localID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo=%q", got)
	}
}

func TestClientInitiatedRekeyKeepsSessionID(t *testing.T) {
	t.Parallel()

	client, policy := startAuthenticatedLoopback(t)
	defer client.conn.Close()
	firstID := append([]byte(nil), client.sessionID...)
	remoteID, localID, err := client.openDirectTCPIP(policy.Target)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.rekey(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(client.sessionID, firstID) {
		t.Fatal("session ID changed across rekey")
	}
	payload := []byte("after-rekey")
	if err := client.sendData(remoteID, payload); err != nil {
		t.Fatal(err)
	}
	got, err := client.recvData(localID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo=%q", got)
	}
	if err := client.rekey(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(client.sessionID, firstID) {
		t.Fatal("session ID changed across second rekey")
	}
}

func TestServerInitiatedRekeyKeepsSessionID(t *testing.T) {
	t.Parallel()

	client, policy := startAuthenticatedLoopbackWith(t, func(p *Policy) {
		p.RekeyAfter = 256
	})
	defer client.conn.Close()
	firstID := append([]byte(nil), client.sessionID...)
	remoteID, localID, err := client.openDirectTCPIP(policy.Target)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("server-rekey"), 256)
	for i := 0; i < 4; i++ {
		if err := client.sendData(remoteID, payload); err != nil {
			t.Fatal(err)
		}
		got, err := client.recvExact(localID, remoteID, len(payload))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo round %d", i)
		}
	}
	if !bytes.Equal(client.sessionID, firstID) {
		t.Fatal("session ID changed across server-initiated rekey")
	}
}

func TestChannelQuotaRejectsExcess(t *testing.T) {
	t.Parallel()

	client, policy := startAuthenticatedLoopbackWith(t, func(p *Policy) {
		p.MaxChannels = 1
	})
	defer client.conn.Close()
	if _, _, err := client.openDirectTCPIP(policy.Target); err != nil {
		t.Fatal(err)
	}
	_, _, err := client.openDirectTCPIP(policy.Target)
	if err == nil {
		t.Fatal("second channel accepted")
	}
	if !strings.Contains(err.Error(), "CHANNEL_OPEN") {
		t.Fatalf("err=%v", err)
	}
}

func TestSourceLimiterEnforcesQuota(t *testing.T) {
	t.Parallel()

	limiter := &sourceLimiter{limit: 1}
	if !limiter.acquire("192.0.2.1") {
		t.Fatal("first acquire failed")
	}
	if limiter.acquire("192.0.2.1") {
		t.Fatal("source quota not enforced")
	}
	if !limiter.acquire("192.0.2.2") {
		t.Fatal("other source blocked")
	}
	limiter.release("192.0.2.1")
	if !limiter.acquire("192.0.2.1") {
		t.Fatal("release did not free quota")
	}
}

type loopbackClient struct {
	conn                 net.Conn
	reader               *bufio.Reader
	clearIn, clearOut    bool
	in, out              packetCodec
	inSeq, outSeq        uint64
	nextLocal            uint32
	clientID, serverID   string
	clientKex, serverKex []byte
	sessionID            []byte
	userKey              composite.PrivateKey
	policy               Policy
	recvBuf              map[uint32][]byte
}

func (c *loopbackClient) handshake() error {
	if _, err := io.WriteString(c.conn, c.clientID+"\r\n"); err != nil {
		return err
	}
	ident, err := c.reader.ReadString('\n')
	if err != nil {
		return err
	}
	c.serverID = trimCRLF(ident)
	c.serverKex, err = c.read()
	if err != nil {
		return err
	}
	if len(c.serverKex) == 0 || c.serverKex[0] != sshMsgKexInit {
		return fmt.Errorf("first packet is not KEXINIT")
	}
	c.clientKex, err = c.policy.marshalKexInitClient()
	if err != nil {
		return err
	}
	if err := c.write(c.clientKex); err != nil {
		return err
	}
	return c.completeKEX()
}

func (c *loopbackClient) rekey() error {
	clientKex, err := c.policy.marshalKexInitClient()
	if err != nil {
		return err
	}
	c.clientKex = clientKex
	if err := c.write(clientKex); err != nil {
		return err
	}
	for {
		pkt, err := c.read()
		if err != nil {
			return err
		}
		if len(pkt) == 0 {
			continue
		}
		if pkt[0] == sshMsgKexInit {
			c.serverKex = pkt
			break
		}
		if pkt[0] == sshMsgChannelData {
			localID, rest, err := consumeUint32(pkt[1:])
			if err != nil {
				return err
			}
			data, _, err := consumeSSHString(rest)
			if err != nil {
				return err
			}
			if c.recvBuf == nil {
				c.recvBuf = map[uint32][]byte{}
			}
			c.recvBuf[localID] = append(c.recvBuf[localID], data...)
			continue
		}
		if pkt[0] == sshMsgIgnore || pkt[0] == sshMsgDebug || pkt[0] == sshMsgGlobalRequest {
			continue
		}
		return fmt.Errorf("unexpected message during rekey %v", msgType(pkt))
	}
	return c.completeKEX()
}

func (c *loopbackClient) completeKEX() error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}
	clientX, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return err
	}
	clientPub := append(append([]byte{}, dk.EncapsulationKey().Bytes()...), clientX.PublicKey().Bytes()...)
	initPkt := append([]byte{sshMsgKexECDHInit}, sshString(clientPub)...)
	if err := c.write(initPkt); err != nil {
		return err
	}
	reply, err := c.read()
	if err != nil {
		return err
	}
	if len(reply) == 0 || reply[0] != sshMsgKexECDHReply {
		return fmt.Errorf("expected KEX_ECDH_REPLY, got %v", msgType(reply))
	}
	hostBlob, rest, err := consumeSSHString(reply[1:])
	if err != nil {
		return err
	}
	serverPub, rest, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	sigBlob, rest, err := consumeSSHString(rest)
	if err != nil || len(rest) != 0 {
		return fmt.Errorf("KEX_ECDH_REPLY trailing bytes")
	}
	shared, err := clientHybridDecapsulate(dk, clientX, serverPub)
	if err != nil {
		return err
	}
	secret := sshString(shared)
	hash := exchangeHash(c.clientID, c.serverID, c.clientKex, c.serverKex, hostBlob, clientPub, serverPub, secret)
	if len(c.sessionID) == 0 {
		c.sessionID = append([]byte(nil), hash...)
	}
	alg, sigRest, err := consumeSSHString(sigBlob)
	if err != nil || string(alg) != composite.Algorithm {
		return fmt.Errorf("host signature algorithm")
	}
	rawSig, sigRest, err := consumeSSHString(sigRest)
	if err != nil || len(sigRest) != 0 {
		return fmt.Errorf("host signature blob")
	}
	alg2, keyRest, err := consumeSSHString(hostBlob)
	if err != nil || string(alg2) != composite.Algorithm {
		return fmt.Errorf("host key algorithm")
	}
	rawHost, keyRest, err := consumeSSHString(keyRest)
	if err != nil || len(keyRest) != 0 {
		return fmt.Errorf("host key blob")
	}
	if err := composite.Verify(rawHost, hash, rawSig); err != nil {
		return err
	}
	keyC, keyD := deriveKeys(secret, hash, c.sessionID)
	pendingOut, err := newChaChaDirection(keyC)
	if err != nil {
		return err
	}
	pendingIn, err := newChaChaDirection(keyD)
	if err != nil {
		return err
	}
	if err := c.write([]byte{sshMsgNewKeys}); err != nil {
		return err
	}
	c.outSeq = 0
	newKeys, err := c.read()
	if err != nil {
		return err
	}
	if len(newKeys) == 0 || newKeys[0] != sshMsgNewKeys {
		return fmt.Errorf("expected NEWKEYS, got %v", msgType(newKeys))
	}
	c.out = pendingOut
	c.in = pendingIn
	c.clearOut = false
	c.clearIn = false
	c.inSeq = 0
	return nil
}

func (c *loopbackClient) completePeerRekey(serverKex []byte) error {
	c.serverKex = serverKex
	clientKex, err := c.policy.marshalKexInitClient()
	if err != nil {
		return err
	}
	c.clientKex = clientKex
	if err := c.write(clientKex); err != nil {
		return err
	}
	return c.completeKEX()
}

func (c *loopbackClient) authenticate() error {
	req := []byte{sshMsgServiceRequest}
	req = append(req, sshString([]byte("ssh-userauth"))...)
	if err := c.write(req); err != nil {
		return err
	}
	accept, err := c.read()
	if err != nil {
		return err
	}
	if len(accept) == 0 || accept[0] != sshMsgServiceAccept {
		return fmt.Errorf("expected SERVICE_ACCEPT, got %v", msgType(accept))
	}
	user := []byte(server.DefaultDedicatedUser)
	service := []byte("ssh-connection")
	pub, err := c.userKey.Public()
	if err != nil {
		return err
	}
	pubBlob := hostKeyBlob(pub)
	auth := []byte{sshMsgUserauthRequest}
	auth = append(auth, sshString(user)...)
	auth = append(auth, sshString(service)...)
	auth = append(auth, sshString([]byte("publickey"))...)
	auth = append(auth, 1)
	auth = append(auth, sshString([]byte(composite.Algorithm))...)
	auth = append(auth, sshString(pubBlob)...)
	signed := sshString(c.sessionID)
	signed = append(signed, sshMsgUserauthRequest)
	signed = append(signed, sshString(user)...)
	signed = append(signed, sshString(service)...)
	signed = append(signed, sshString([]byte("publickey"))...)
	signed = append(signed, 1)
	signed = append(signed, sshString([]byte(composite.Algorithm))...)
	signed = append(signed, sshString(pubBlob)...)
	rawSig, err := c.userKey.Sign(signed)
	if err != nil {
		return err
	}
	auth = append(auth, sshString(signatureBlob(rawSig))...)
	if err := c.write(auth); err != nil {
		return err
	}
	ok, err := c.read()
	if err != nil {
		return err
	}
	if len(ok) == 0 || ok[0] != sshMsgUserauthSuccess {
		return fmt.Errorf("expected USERAUTH_SUCCESS, got %v", msgType(ok))
	}
	return nil
}

func (c *loopbackClient) openDirectTCPIP(dest netip.AddrPort) (remoteID, localID uint32, err error) {
	localID = c.nextLocal
	c.nextLocal++
	pkt := []byte{sshMsgChannelOpen}
	pkt = append(pkt, sshString([]byte(channelDirectTCPIP))...)
	pkt = binary.BigEndian.AppendUint32(pkt, localID)
	pkt = binary.BigEndian.AppendUint32(pkt, 2<<20)
	pkt = binary.BigEndian.AppendUint32(pkt, 32<<10)
	pkt = append(pkt, sshString([]byte(dest.Addr().String()))...)
	pkt = binary.BigEndian.AppendUint32(pkt, uint32(dest.Port()))
	pkt = append(pkt, sshString([]byte("127.0.0.1"))...)
	pkt = binary.BigEndian.AppendUint32(pkt, 0)
	if err := c.write(pkt); err != nil {
		return 0, 0, err
	}
	confirm, err := c.read()
	if err != nil {
		return 0, 0, err
	}
	if len(confirm) == 0 || confirm[0] != sshMsgChannelOpenConfirm {
		return 0, 0, fmt.Errorf("expected CHANNEL_OPEN_CONFIRMATION, got %v", msgType(confirm))
	}
	recipient, rest, err := consumeUint32(confirm[1:])
	if err != nil || recipient != localID {
		return 0, 0, fmt.Errorf("channel confirmation recipient")
	}
	remoteID, _, err = consumeUint32(rest)
	if err != nil {
		return 0, 0, err
	}
	return remoteID, localID, nil
}

func (c *loopbackClient) sendData(remoteID uint32, data []byte) error {
	pkt := []byte{sshMsgChannelData}
	pkt = binary.BigEndian.AppendUint32(pkt, remoteID)
	pkt = append(pkt, sshString(data)...)
	return c.write(pkt)
}

func (c *loopbackClient) closeRemote(remoteID uint32) error {
	pkt := []byte{sshMsgChannelClose}
	pkt = binary.BigEndian.AppendUint32(pkt, remoteID)
	return c.write(pkt)
}

func (c *loopbackClient) creditWindow(remoteID, add uint32) error {
	pkt := []byte{sshMsgChannelWindowAdjust}
	pkt = binary.BigEndian.AppendUint32(pkt, remoteID)
	pkt = binary.BigEndian.AppendUint32(pkt, add)
	return c.write(pkt)
}

func (c *loopbackClient) recvExact(localID, remoteID uint32, want int) ([]byte, error) {
	if c.recvBuf == nil {
		c.recvBuf = map[uint32][]byte{}
	}
	var out []byte
	if buf := c.recvBuf[localID]; len(buf) > 0 {
		n := want
		if n > len(buf) {
			n = len(buf)
		}
		out = append(out, buf[:n]...)
		c.recvBuf[localID] = buf[n:]
	}
	for len(out) < want {
		chunk, err := c.recvData(localID)
		if err != nil {
			return nil, err
		}
		if err := c.creditWindow(remoteID, uint32(len(chunk))); err != nil {
			return nil, err
		}
		need := want - len(out)
		if len(chunk) <= need {
			out = append(out, chunk...)
			continue
		}
		out = append(out, chunk[:need]...)
		c.recvBuf[localID] = append(append([]byte{}, c.recvBuf[localID]...), chunk[need:]...)
	}
	return out, nil
}

func (c *loopbackClient) recvData(localID uint32) ([]byte, error) {
	for {
		pkt, err := c.read()
		if err != nil {
			return nil, err
		}
		if len(pkt) == 0 {
			continue
		}
		switch pkt[0] {
		case sshMsgIgnore, sshMsgDebug, sshMsgExtInfo, sshMsgChannelWindowAdjust:
			continue
		case sshMsgKexInit:
			if err := c.completePeerRekey(pkt); err != nil {
				return nil, err
			}
			continue
		case sshMsgChannelData:
			gotID, rest, err := consumeUint32(pkt[1:])
			if err != nil {
				return nil, err
			}
			if gotID != localID {
				continue
			}
			data, _, err := consumeSSHString(rest)
			return data, err
		default:
			return nil, fmt.Errorf("expected CHANNEL_DATA, got %v", msgType(pkt))
		}
	}
}

func (c *loopbackClient) write(payload []byte) error {
	if c.clearOut {
		if err := writePacket(c.conn, payload); err != nil {
			return err
		}
		c.outSeq++
		return nil
	}
	frame, err := c.out.seal(c.outSeq, payload)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(frame); err != nil {
		return err
	}
	c.outSeq++
	return nil
}

func (c *loopbackClient) read() ([]byte, error) {
	if c.clearIn {
		payload, err := readClearPacket(c.reader)
		if err != nil {
			return nil, err
		}
		c.inSeq++
		return payload, nil
	}
	payload, err := c.in.open(c.inSeq, c.reader)
	if err != nil {
		return nil, err
	}
	c.inSeq++
	return payload, nil
}

type loopbackServer struct {
	policy  Policy
	userKey composite.PrivateKey
	errCh   <-chan error
}

func startAuthenticatedLoopback(t testing.TB) (*loopbackClient, Policy) {
	t.Helper()
	return startAuthenticatedLoopbackWith(t, nil)
}

func startAuthenticatedLoopbackWith(t testing.TB, tweak func(*Policy)) (*loopbackClient, Policy) {
	t.Helper()
	server := startLoopbackServerWith(t, tweak)
	client := server.dial(t)
	t.Cleanup(func() { _ = client.conn.Close() })
	return client, server.policy
}

func startLoopbackServer(t testing.TB) loopbackServer {
	t.Helper()
	return startLoopbackServerWith(t, nil)
}

func startLoopbackServerWith(t testing.TB, tweak func(*Policy)) loopbackServer {
	t.Helper()

	_, backendAddr := startEchoBackend(t)
	hostKey, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := composite.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hostPEM, err := opensshkey.MarshalPrivate(hostKey, "host")
	if err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(dir, "host")
	if err := os.WriteFile(hostPath, hostPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	userPub, err := userKey.Public()
	if err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(dir, "authorized_keys")
	line := composite.Algorithm + " " + base64.StdEncoding.EncodeToString(hostKeyBlob(userPub)) + "\n"
	if err := os.WriteFile(authPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := listener.Addr().(*net.TCPAddr)
	policy := mustPolicy(t)
	policy.Listen = netip.MustParseAddrPort(listenAddr.String())
	policy.Target = backendAddr
	policy.HostKeyPath = hostPath
	policy.AuthorizedKeysPath = authPath
	if tweak != nil {
		tweak(&policy)
	}
	hostPEMBytes, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	parsedHost, err := opensshkey.ParsePrivate(hostPEMBytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveListener(ctx, listener, policy, nil, parsedHost)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	})
	return loopbackServer{policy: policy, userKey: userKey, errCh: errCh}
}

func (s loopbackServer) dial(t testing.TB) *loopbackClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.policy.Listen.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	client := &loopbackClient{
		conn:     conn,
		reader:   bufio.NewReader(conn),
		clearIn:  true,
		clearOut: true,
		clientID: "SSH-2.0-WarpTweetTest",
		userKey:  s.userKey,
		policy:   s.policy,
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	if err := client.authenticate(); err != nil {
		t.Fatal(err)
	}
	return client
}

func startEchoBackend(t testing.TB) (net.Listener, netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	ip, _ := netip.AddrFromSlice(addr.IP)
	return ln, netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port))
}

func trimCRLF(s string) string {
	return strings.TrimRight(s, "\r\n")
}

func msgType(payload []byte) any {
	if len(payload) == 0 {
		return "empty"
	}
	return payload[0]
}

func TestRecvExactKeepsSurplus(t *testing.T) {
	t.Parallel()

	c := &loopbackClient{recvBuf: map[uint32][]byte{3: []byte("abcdef")}}
	got, err := c.recvExact(3, 9, 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ab" {
		t.Fatalf("got=%q", got)
	}
	if string(c.recvBuf[3]) != "cdef" {
		t.Fatalf("buf=%q", c.recvBuf[3])
	}
	got, err = c.recvExact(3, 9, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "cde" {
		t.Fatalf("got=%q", got)
	}
	if string(c.recvBuf[3]) != "f" {
		t.Fatalf("buf=%q", c.recvBuf[3])
	}
}
