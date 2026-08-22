package dataplane

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/grantsession"
	"warptweet.com/warptweet/internal/server"
)

const (
	sshMsgDisconnect           = 1
	sshMsgIgnore               = 2
	sshMsgUnimplemented        = 3
	sshMsgDebug                = 4
	sshMsgServiceRequest       = 5
	sshMsgServiceAccept        = 6
	sshMsgExtInfo              = 7
	sshMsgKexECDHInit          = 30
	sshMsgKexECDHReply         = 31
	sshMsgNewKeys              = 21
	sshMsgUserauthRequest      = 50
	sshMsgUserauthFailure      = 51
	sshMsgUserauthSuccess      = 52
	sshMsgUserauthPKOK         = 60
	sshMsgGlobalRequest        = 80
	sshMsgRequestSuccess       = 81
	sshMsgRequestFailure       = 82
	sshMsgChannelOpen          = 90
	sshMsgChannelOpenConfirm   = 91
	sshMsgChannelOpenFailure   = 92
	sshMsgChannelWindowAdjust  = 93
	sshMsgChannelData          = 94
	sshMsgChannelEOF           = 96
	sshMsgChannelClose         = 97
	sshMsgChannelRequest       = 98
	sshMsgChannelSuccess       = 99
	sshMsgChannelFailure       = 100
	channelOpenAdminProhibited = 1
	handshakeTimeout           = 15 * time.Second
	sessionIdleTimeout         = 5 * time.Minute
	windowAdjustThreshold      = 1 << 20
	maxSSHSeq                  = uint64(^uint32(0))
)

type connection struct {
	conn                 net.Conn
	reader               *bufio.Reader
	policy               Policy
	hostKey              composite.PrivateKey
	clients              [][]byte
	clearIn, clearOut    bool
	in, out              packetCodec
	inSeq, outSeq        uint64
	clientID, serverID   string
	clientKex, serverKex []byte
	sessionID            []byte
	authed               bool
	mu                   sync.Mutex
	win                  *sync.Cond
	channels             map[uint32]*sshChannel
	nextLocal            uint32
	grant                *grantsession.Authority
	sessions             *sessionTable
	connectionID         string
	keyDigest            string
}

type sshChannel struct {
	localID  uint32
	remoteID uint32
	window   uint32
	maxPkt   uint32
	consumed uint32
	closed   bool
	backend  net.Conn
}

func serveConnection(raw net.Conn, policy Policy, hostKey composite.PrivateKey, clients [][]byte, sessions *sessionTable) error {
	c := &connection{
		conn:     raw,
		reader:   bufio.NewReader(raw),
		policy:   policy,
		hostKey:  hostKey,
		clients:  clients,
		clearIn:  true,
		clearOut: true,
		channels: map[uint32]*sshChannel{},
		grant:    policy.Grant,
		sessions: sessions,
	}
	c.win = sync.NewCond(&c.mu)
	defer raw.Close()
	defer c.releaseGrant()
	defer c.teardownChannels()
	return c.serve()
}

func (c *connection) serve() error {
	c.serverID = c.policy.identification()
	if _, err := io.WriteString(c.conn, c.serverID+"\r\n"); err != nil {
		return err
	}
	clientID, err := c.readIdentification()
	if err != nil {
		return err
	}
	c.clientID = clientID
	serverKex, err := c.policy.marshalKexInit()
	if err != nil {
		return err
	}
	c.serverKex = serverKex
	if err := c.write(serverKex); err != nil {
		return err
	}
	for {
		payload, err := c.read()
		if err != nil {
			return err
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case sshMsgKexInit:
			c.clientKex = payload
		case sshMsgKexECDHInit:
			if err := c.handleKEX(payload); err != nil {
				return err
			}
		case sshMsgNewKeys:
			if c.in == nil {
				return fmt.Errorf("NEWKEYS before key derivation")
			}
			c.clearIn = false
		case sshMsgIgnore, sshMsgUnimplemented, sshMsgDebug, sshMsgExtInfo:
		case sshMsgDisconnect:
			return nil
		case sshMsgServiceRequest, sshMsgUserauthRequest, sshMsgGlobalRequest,
			sshMsgChannelOpen, sshMsgChannelData, sshMsgChannelWindowAdjust,
			sshMsgChannelEOF, sshMsgChannelClose, sshMsgChannelRequest:
			if err := c.dispatchSecure(payload); err != nil {
				return err
			}
		default:
			return c.disconnect(fmt.Sprintf("unexpected SSH message %d", payload[0]))
		}
	}
}

func (c *connection) dispatchSecure(payload []byte) error {
	if c.clearIn {
		return c.disconnect("post-KEX message before NEWKEYS")
	}
	switch payload[0] {
	case sshMsgServiceRequest:
		return c.handleService(payload)
	case sshMsgUserauthRequest:
		return c.handleUserauth(payload)
	case sshMsgGlobalRequest:
		return c.handleGlobal(payload)
	case sshMsgChannelOpen:
		return c.handleChannelOpen(payload)
	case sshMsgChannelData:
		return c.handleChannelData(payload)
	case sshMsgChannelWindowAdjust:
		return c.handleWindowAdjust(payload)
	case sshMsgChannelEOF:
		return c.handleChannelEOF(payload)
	case sshMsgChannelClose:
		return c.handleChannelClose(payload)
	case sshMsgChannelRequest:
		return c.handleChannelRequest(payload)
	default:
		return c.disconnect(fmt.Sprintf("unexpected SSH message %d", payload[0]))
	}
}

func (c *connection) handleKEX(payload []byte) error {
	if c.clientKex == nil {
		return fmt.Errorf("KEX_ECDH_INIT before KEXINIT")
	}
	clientPub, rest, err := consumeSSHString(payload[1:])
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing KEX_ECDH_INIT bytes")
	}
	serverPub, shared, err := serverHybridEncapsulate(clientPub)
	if err != nil {
		return err
	}
	if err := clientOffersPinnedAlgorithms(c.clientKex, c.policy); err != nil {
		return c.disconnect(err.Error())
	}
	hostPub, err := c.hostKey.Public()
	if err != nil {
		return err
	}
	hostBlob := hostKeyBlob(hostPub)
	secret := sshString(shared)
	hash := exchangeHash(c.clientID, c.serverID, c.clientKex, c.serverKex, hostBlob, clientPub, serverPub, secret)
	c.sessionID = append([]byte(nil), hash...)
	sigRaw, err := c.hostKey.Sign(hash)
	if err != nil {
		return err
	}
	reply := []byte{sshMsgKexECDHReply}
	reply = append(reply, sshString(hostBlob)...)
	reply = append(reply, sshString(serverPub)...)
	reply = append(reply, sshString(signatureBlob(sigRaw))...)
	if err := c.write(reply); err != nil {
		return err
	}
	keyC, keyD := deriveKeys(secret, hash)
	c.out, err = newChaChaDirection(keyD)
	if err != nil {
		return err
	}
	c.in, err = newChaChaDirection(keyC)
	if err != nil {
		return err
	}
	if err := c.write([]byte{sshMsgNewKeys}); err != nil {
		return err
	}
	c.clearOut = false
	return nil
}

func (c *connection) handleService(payload []byte) error {
	name, rest, err := consumeSSHString(payload[1:])
	if err != nil {
		return err
	}
	if len(rest) != 0 || string(name) != "ssh-userauth" {
		return c.disconnect("WarpTweet only accepts ssh-userauth")
	}
	out := []byte{sshMsgServiceAccept}
	out = append(out, sshString([]byte("ssh-userauth"))...)
	return c.write(out)
}

func (c *connection) handleUserauth(payload []byte) error {
	user, rest, err := consumeSSHString(payload[1:])
	if err != nil {
		return err
	}
	service, rest, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	method, rest, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	if string(user) != server.DefaultDedicatedUser || string(service) != "ssh-connection" || string(method) != "publickey" {
		return c.write(userauthFailure())
	}
	hasSig, rest, err := consumeBool(rest)
	if err != nil {
		return err
	}
	alg, rest, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	pubBlob, rest, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	if string(alg) != composite.Algorithm {
		return c.write(userauthFailure())
	}
	alg2, restBlob, err := consumeSSHString(pubBlob)
	if err != nil || string(alg2) != composite.Algorithm {
		return c.write(userauthFailure())
	}
	rawPub, restBlob, err := consumeSSHString(restBlob)
	if err != nil || len(restBlob) != 0 {
		return c.write(userauthFailure())
	}
	if !c.knownClient(rawPub) {
		return c.write(userauthFailure())
	}
	if !hasSig {
		if len(rest) != 0 {
			return c.write(userauthFailure())
		}
		ok := []byte{sshMsgUserauthPKOK}
		ok = append(ok, sshString([]byte(composite.Algorithm))...)
		ok = append(ok, sshString(pubBlob)...)
		return c.write(ok)
	}
	sigWire, rest, err := consumeSSHString(rest)
	if err != nil || len(rest) != 0 {
		return c.write(userauthFailure())
	}
	alg3, sigRest, err := consumeSSHString(sigWire)
	if err != nil || string(alg3) != composite.Algorithm {
		return c.write(userauthFailure())
	}
	rawSig, sigRest, err := consumeSSHString(sigRest)
	if err != nil || len(sigRest) != 0 {
		return c.write(userauthFailure())
	}
	signed := sshString(c.sessionID)
	signed = append(signed, sshMsgUserauthRequest)
	signed = append(signed, sshString([]byte(user))...)
	signed = append(signed, sshString([]byte(service))...)
	signed = append(signed, sshString([]byte("publickey"))...)
	signed = append(signed, 1)
	signed = append(signed, sshString([]byte(composite.Algorithm))...)
	signed = append(signed, sshString(pubBlob)...)
	if err := composite.Verify(rawPub, signed, rawSig); err != nil {
		return c.write(userauthFailure())
	}
	c.authed = true
	sum := sha256.Sum256(hostKeyBlob(rawPub))
	c.keyDigest = hex.EncodeToString(sum[:])
	connID, err := newConnectionID()
	if err != nil {
		return err
	}
	c.connectionID = connID
	if c.grant != nil {
		if _, err := c.grant.Register(os.Getpid(), c.keyDigest, c.connectionID); err != nil {
			return c.disconnect("grant session registration failed")
		}
		if c.sessions != nil {
			c.sessions.track(c)
		}
	}
	_ = c.conn.SetDeadline(time.Now().Add(sessionIdleTimeout))
	return c.write([]byte{sshMsgUserauthSuccess})
}

func (c *connection) releaseGrant() {
	if c.sessions != nil {
		c.sessions.untrack(c.connectionID)
	}
	if c.grant != nil && c.connectionID != "" {
		_ = c.grant.UnregisterConnection(os.Getpid(), c.connectionID)
	}
}

func newConnectionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (c *connection) knownClient(rawPub []byte) bool {
	for _, known := range c.clients {
		if string(known) == string(rawPub) {
			return true
		}
	}
	return false
}

func (c *connection) handleGlobal(payload []byte) error {
	name, rest, err := consumeSSHString(payload[1:])
	if err != nil {
		return err
	}
	wantReply, rest, err := consumeBool(rest)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return c.disconnect("trailing global-request payload")
	}
	if err := c.policy.allowGlobalRequest(string(name)); err != nil {
		if wantReply {
			return c.write([]byte{sshMsgRequestFailure})
		}
		return nil
	}
	if wantReply {
		return c.write([]byte{sshMsgRequestSuccess})
	}
	return nil
}

func userauthFailure() []byte {
	out := []byte{sshMsgUserauthFailure}
	out = append(out, sshString([]byte("publickey"))...)
	out = append(out, 0)
	return out
}

func (c *connection) readIdentification() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "SSH-2.0-") || len(line) > maxIdentificationBytes {
		return "", fmt.Errorf("unsupported identification %q", line)
	}
	return line, nil
}

func checkSSHSeq(seq uint64) error {
	if seq > maxSSHSeq {
		return fmt.Errorf("SSH packet sequence exhausted")
	}
	return nil
}

func (c *connection) write(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authed {
		_ = c.conn.SetDeadline(time.Now().Add(sessionIdleTimeout))
	}
	if err := checkSSHSeq(c.outSeq); err != nil {
		return err
	}
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

func (c *connection) read() ([]byte, error) {
	if c.authed {
		_ = c.conn.SetDeadline(time.Now().Add(sessionIdleTimeout))
	}
	if err := checkSSHSeq(c.inSeq); err != nil {
		return nil, err
	}
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

func (c *connection) teardownChannels() {
	c.mu.Lock()
	channels := make([]*sshChannel, 0, len(c.channels))
	for id, ch := range c.channels {
		ch.closed = true
		delete(c.channels, id)
		channels = append(channels, ch)
	}
	c.win.Broadcast()
	c.mu.Unlock()
	for _, ch := range channels {
		if ch.backend != nil {
			_ = ch.backend.Close()
		}
	}
}

func (c *connection) disconnect(reason string) error {
	_ = c.write(marshalDisconnect(reason))
	return fmt.Errorf("%s", reason)
}

func authorizedRawKeys(contents []byte) ([][]byte, error) {
	var keys [][]byte
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		idx := -1
		for i, field := range fields {
			if field == composite.Algorithm {
				idx = i
				break
			}
		}
		if idx < 0 || idx+1 >= len(fields) {
			continue
		}
		blob := fields[idx+1]
		raw, err := decodePublicBlob(blob)
		if err != nil {
			return nil, err
		}
		keys = append(keys, raw)
	}
	return keys, nil
}

func decodePublicBlob(blob string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(blob)
	if err != nil {
		return nil, err
	}
	alg, rest, err := consumeSSHString(decoded)
	if err != nil {
		return nil, err
	}
	if string(alg) != composite.Algorithm {
		return nil, fmt.Errorf("authorized key algorithm %q", alg)
	}
	raw, rest, err := consumeSSHString(rest)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("authorized key blob")
	}
	return raw, nil
}

func exchangeHash(clientID, serverID string, clientKex, serverKex, hostBlob, clientPub, serverPub, secret []byte) []byte {
	var b []byte
	b = append(b, sshString([]byte(clientID))...)
	b = append(b, sshString([]byte(serverID))...)
	b = appendKexInitHash(b, clientKex)
	b = appendKexInitHash(b, serverKex)
	b = append(b, sshString(hostBlob)...)
	b = append(b, sshString(clientPub)...)
	b = append(b, sshString(serverPub)...)
	b = append(b, secret...)
	sum := sha256.Sum256(b)
	return sum[:]
}

func appendKexInitHash(dst, kex []byte) []byte {
	body := kex
	if len(body) > 0 && body[0] == sshMsgKexInit {
		body = body[1:]
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)+1))
	dst = append(dst, sshMsgKexInit)
	return append(dst, body...)
}

func deriveKeys(secret, hash []byte) (keyC, keyD []byte) {
	return deriveOne(secret, hash, hash, 'C', chachaKeyTotal),
		deriveOne(secret, hash, hash, 'D', chachaKeyTotal)
}

func clientOffersPinnedAlgorithms(kex []byte, policy Policy) error {
	body := kex
	if len(body) > 0 && body[0] == sshMsgKexInit {
		body = body[1:]
	}
	if len(body) < 16 {
		return fmt.Errorf("truncated client KEXINIT")
	}
	body = body[16:]
	kexList, body, err := consumeSSHString(body)
	if err != nil {
		return err
	}
	hostList, body, err := consumeSSHString(body)
	if err != nil {
		return err
	}
	c2s, body, err := consumeSSHString(body)
	if err != nil {
		return err
	}
	s2c, _, err := consumeSSHString(body)
	if err != nil {
		return err
	}
	if !nameListContains(string(kexList), policy.Profile.KeyExchangeAlgorithm) {
		return fmt.Errorf("client KEXINIT missing %s", policy.Profile.KeyExchangeAlgorithm)
	}
	if !nameListContains(string(hostList), policy.Profile.AuthenticationKeyType) {
		return fmt.Errorf("client KEXINIT missing %s", policy.Profile.AuthenticationKeyType)
	}
	cipherName := policy.Profile.Ciphers[0]
	if !nameListContains(string(c2s), cipherName) || !nameListContains(string(s2c), cipherName) {
		return fmt.Errorf("client KEXINIT missing %s", cipherName)
	}
	return nil
}

func nameListContains(list, want string) bool {
	for _, name := range strings.Split(list, ",") {
		if name == want {
			return true
		}
	}
	return false
}

func deriveOne(secret, hash, sessionID []byte, id byte, need int) []byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(hash)
	h.Write([]byte{id})
	h.Write(sessionID)
	digest := h.Sum(nil)
	for len(digest) < need {
		h.Reset()
		h.Write(secret)
		h.Write(hash)
		h.Write(digest)
		digest = append(digest, h.Sum(nil)...)
	}
	return digest[:need]
}
