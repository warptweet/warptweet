package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"
)

func (c *connection) handleChannelOpen(payload []byte) error {
	if !c.authed {
		return c.disconnect("channel open before authentication")
	}
	name, rest, err := consumeSSHString(payload[1:])
	if err != nil {
		return err
	}
	sender, rest, err := consumeUint32(rest)
	if err != nil {
		return err
	}
	window, rest, err := consumeUint32(rest)
	if err != nil {
		return err
	}
	maxPkt, rest, err := consumeUint32(rest)
	if err != nil {
		return err
	}
	if maxPkt == 0 {
		return c.channelOpenFailure(sender, "max packet size is zero")
	}
	if err := c.policy.allowChannelType(string(name)); err != nil {
		return c.channelOpenFailure(sender, err.Error())
	}
	host, rest, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	port, rest, err := consumeUint32(rest)
	if err != nil {
		return err
	}
	_ = rest
	addr, err := netip.ParseAddr(string(host))
	if err != nil {
		return c.channelOpenFailure(sender, "destination is not a numeric address")
	}
	dest := netip.AddrPortFrom(addr.Unmap(), uint16(port))
	if err := c.policy.allowDirectTCPIP(dest); err != nil {
		return c.channelOpenFailure(sender, err.Error())
	}
	backend, err := net.Dial("tcp", dest.String())
	if err != nil {
		return c.channelOpenFailure(sender, err.Error())
	}
	c.mu.Lock()
	localID := c.nextLocal
	c.nextLocal++
	ch := &sshChannel{
		localID:  localID,
		remoteID: sender,
		window:   window,
		maxPkt:   maxPkt,
		backend:  backend,
	}
	c.channels[localID] = ch
	c.mu.Unlock()
	confirm := []byte{sshMsgChannelOpenConfirm}
	confirm = binary.BigEndian.AppendUint32(confirm, sender)
	confirm = binary.BigEndian.AppendUint32(confirm, localID)
	confirm = binary.BigEndian.AppendUint32(confirm, 2<<20)
	confirm = binary.BigEndian.AppendUint32(confirm, 32<<10)
	if err := c.write(confirm); err != nil {
		c.closeChannel(localID)
		return err
	}
	go c.forwardBackend(ch)
	return nil
}

func (c *connection) channelOpenFailure(sender uint32, reason string) error {
	out := []byte{sshMsgChannelOpenFailure}
	out = binary.BigEndian.AppendUint32(out, sender)
	out = binary.BigEndian.AppendUint32(out, channelOpenAdminProhibited)
	out = append(out, sshString([]byte(reason))...)
	out = append(out, sshString(nil)...)
	return c.write(out)
}

func (c *connection) forwardBackend(ch *sshChannel) {
	buf := make([]byte, 16<<10)
	for {
		n, err := ch.backend.Read(buf)
		if n > 0 {
			if werr := c.sendChannelData(ch, buf[:n]); werr != nil {
				c.closeChannel(ch.localID)
				return
			}
		}
		if err != nil {
			eof := []byte{sshMsgChannelEOF}
			eof = binary.BigEndian.AppendUint32(eof, ch.remoteID)
			_ = c.write(eof)
			c.closeChannel(ch.localID)
			return
		}
	}
}

func (c *connection) sendChannelData(ch *sshChannel, data []byte) error {
	for len(data) > 0 {
		c.mu.Lock()
		for !ch.closed && ch.window == 0 {
			c.win.Wait()
		}
		if ch.closed {
			c.mu.Unlock()
			return net.ErrClosed
		}
		chunk := uint32(len(data))
		if chunk > ch.maxPkt {
			chunk = ch.maxPkt
		}
		if chunk > ch.window {
			chunk = ch.window
		}
		ch.window -= chunk
		c.mu.Unlock()
		pkt := []byte{sshMsgChannelData}
		pkt = binary.BigEndian.AppendUint32(pkt, ch.remoteID)
		pkt = append(pkt, sshString(data[:chunk])...)
		if err := c.write(pkt); err != nil {
			return err
		}
		data = data[chunk:]
	}
	return nil
}

func (c *connection) handleChannelData(payload []byte) error {
	localID, rest, err := consumeUint32(payload[1:])
	if err != nil {
		return err
	}
	data, _, err := consumeSSHString(rest)
	if err != nil {
		return err
	}
	c.mu.Lock()
	ch := c.channels[localID]
	c.mu.Unlock()
	if ch == nil || ch.backend == nil {
		return nil
	}
	n, err := ch.backend.Write(data)
	if err != nil {
		return err
	}
	c.mu.Lock()
	ch.consumed += uint32(n)
	adjust := ch.consumed
	if adjust < windowAdjustThreshold {
		c.mu.Unlock()
		return nil
	}
	ch.consumed = 0
	remoteID := ch.remoteID
	c.mu.Unlock()
	pkt := []byte{sshMsgChannelWindowAdjust}
	pkt = binary.BigEndian.AppendUint32(pkt, remoteID)
	pkt = binary.BigEndian.AppendUint32(pkt, adjust)
	return c.write(pkt)
}

func (c *connection) handleWindowAdjust(payload []byte) error {
	localID, rest, err := consumeUint32(payload[1:])
	if err != nil {
		return err
	}
	add, _, err := consumeUint32(rest)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := c.channels[localID]
	if ch == nil {
		return nil
	}
	ch.window += add
	c.win.Broadcast()
	return nil
}

func (c *connection) handleChannelEOF(payload []byte) error {
	localID, _, err := consumeUint32(payload[1:])
	if err != nil {
		return err
	}
	c.mu.Lock()
	ch := c.channels[localID]
	c.mu.Unlock()
	if ch == nil || ch.backend == nil {
		return nil
	}
	if tcp, ok := ch.backend.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	return nil
}

func (c *connection) handleChannelClose(payload []byte) error {
	localID, _, err := consumeUint32(payload[1:])
	if err != nil {
		return err
	}
	c.closeChannel(localID)
	return nil
}

func (c *connection) handleChannelRequest(payload []byte) error {
	localID, rest, err := consumeUint32(payload[1:])
	if err != nil {
		return err
	}
	_, rest, err = consumeSSHString(rest)
	if err != nil {
		return err
	}
	wantReply, _, err := consumeBool(rest)
	if err != nil {
		return err
	}
	if !wantReply {
		return nil
	}
	c.mu.Lock()
	ch := c.channels[localID]
	c.mu.Unlock()
	if ch == nil {
		return nil
	}
	out := []byte{sshMsgChannelFailure}
	out = binary.BigEndian.AppendUint32(out, ch.remoteID)
	return c.write(out)
}

func (c *connection) closeChannel(localID uint32) {
	c.mu.Lock()
	ch := c.channels[localID]
	if ch != nil {
		ch.closed = true
		delete(c.channels, localID)
	}
	c.win.Broadcast()
	c.mu.Unlock()
	if ch == nil {
		return
	}
	if ch.backend != nil {
		_ = ch.backend.Close()
	}
	closePkt := []byte{sshMsgChannelClose}
	closePkt = binary.BigEndian.AppendUint32(closePkt, ch.remoteID)
	_ = c.write(closePkt)
}
