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

	backend, backendAddr := startEchoBackend(t)
	defer backend.Close()

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
	_ = listener.Close()

	policy := mustPolicy(t)
	policy.Listen = netip.MustParseAddrPort(listenAddr.String())
	policy.Target = backendAddr
	policy.HostKeyPath = hostPath
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

	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case serveErr := <-errCh:
			t.Fatalf("Serve returned early: %v", serveErr)
		default:
		}
		conn, err = net.DialTimeout("tcp", policy.Listen.String(), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("dial data plane: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	client := &loopbackClient{
		conn:     conn,
		reader:   bufio.NewReader(conn),
		clearIn:  true,
		clearOut: true,
		clientID: "SSH-2.0-WarpTweetTest",
		userKey:  userKey,
		policy:   policy,
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	if err := client.authenticate(); err != nil {
		t.Fatal(err)
	}
	remoteID, err := client.openDirectTCPIP(policy.Target)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("warptweet-loopback")
	if err := client.sendData(remoteID, payload); err != nil {
		t.Fatal(err)
	}
	got, err := client.recvData(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo=%q", got)
	}
}

type loopbackClient struct {
	conn                 net.Conn
	reader               *bufio.Reader
	clearIn, clearOut    bool
	in, out              *gcmDirection
	clientID, serverID   string
	clientKex, serverKex []byte
	sessionID            []byte
	userKey              composite.PrivateKey
	policy               Policy
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
	c.clientKex, err = c.policy.marshalKexInit()
	if err != nil {
		return err
	}
	if err := c.write(c.clientKex); err != nil {
		return err
	}
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
	secret := sshMpint(shared)
	hash := exchangeHash(c.clientID, c.serverID, c.clientKex, c.serverKex, hostBlob, clientPub, serverPub, secret)
	c.sessionID = append([]byte(nil), hash...)
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
	ivA, ivB, keyC, keyD := deriveKeys(secret, hash)
	c.out, err = newGCMDirection(keyC, ivA)
	if err != nil {
		return err
	}
	c.in, err = newGCMDirection(keyD, ivB)
	if err != nil {
		return err
	}
	if err := c.write([]byte{sshMsgNewKeys}); err != nil {
		return err
	}
	c.clearOut = false
	newKeys, err := c.read()
	if err != nil {
		return err
	}
	if len(newKeys) == 0 || newKeys[0] != sshMsgNewKeys {
		return fmt.Errorf("expected NEWKEYS, got %v", msgType(newKeys))
	}
	c.clearIn = false
	return nil
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

func (c *loopbackClient) openDirectTCPIP(dest netip.AddrPort) (uint32, error) {
	pkt := []byte{sshMsgChannelOpen}
	pkt = append(pkt, sshString([]byte(channelDirectTCPIP))...)
	pkt = binary.BigEndian.AppendUint32(pkt, 0)
	pkt = binary.BigEndian.AppendUint32(pkt, 2<<20)
	pkt = binary.BigEndian.AppendUint32(pkt, 32<<10)
	pkt = append(pkt, sshString([]byte(dest.Addr().String()))...)
	pkt = binary.BigEndian.AppendUint32(pkt, uint32(dest.Port()))
	pkt = append(pkt, sshString([]byte("127.0.0.1"))...)
	pkt = binary.BigEndian.AppendUint32(pkt, 0)
	if err := c.write(pkt); err != nil {
		return 0, err
	}
	confirm, err := c.read()
	if err != nil {
		return 0, err
	}
	if len(confirm) == 0 || confirm[0] != sshMsgChannelOpenConfirm {
		return 0, fmt.Errorf("expected CHANNEL_OPEN_CONFIRMATION, got %v", msgType(confirm))
	}
	recipient, rest, err := consumeUint32(confirm[1:])
	if err != nil || recipient != 0 {
		return 0, fmt.Errorf("channel confirmation recipient")
	}
	sender, _, err := consumeUint32(rest)
	if err != nil {
		return 0, err
	}
	return sender, nil
}

func (c *loopbackClient) sendData(remoteID uint32, data []byte) error {
	pkt := []byte{sshMsgChannelData}
	pkt = binary.BigEndian.AppendUint32(pkt, remoteID)
	pkt = append(pkt, sshString(data)...)
	return c.write(pkt)
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
		return writePacket(c.conn, payload)
	}
	frame, err := c.out.seal(payload)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(frame)
	return err
}

func (c *loopbackClient) read() ([]byte, error) {
	if c.clearIn {
		return readClearPacket(c.reader)
	}
	return c.in.open(c.reader)
}

func startEchoBackend(t *testing.T) (net.Listener, netip.AddrPort) {
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
