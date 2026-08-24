package inspectnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// RouteMessage is one RTM_NEWROUTE.
type RouteMessage struct {
	Type       uint16
	Family     uint8
	Table      uint8
	PrefSrc    netip.Addr
	OutIfIndex int
	HasPrefSrc bool
	HasOutIf   bool
}

// RouteReply is a parsed RTM_GETROUTE response plus kernel evidence.
type RouteReply struct {
	Messages []RouteMessage
	Evidence string
}

type netlinkErrno struct {
	Errno int
}

func (err netlinkErrno) Error() string {
	return fmt.Sprintf("netlink RTM_GETROUTE errno %d", err.Errno)
}

func (err netlinkErrno) unreachable() bool {
	switch err.Errno {
	case errnoNetUnreach, errnoHostUnreach, errnoNetDown:
		return true
	default:
		return false
	}
}

// ParseRouteMessages decodes a netlink datagram into RTM_NEWROUTE messages.
func ParseRouteMessages(buf []byte) (RouteReply, error) {
	remaining := buf
	var messages []RouteMessage
	for len(remaining) >= nlmsgHdrLen {
		nlen := int(binary.LittleEndian.Uint32(remaining[0:4]))
		if nlen < nlmsgHdrLen || nlen > len(remaining) {
			return RouteReply{}, fmt.Errorf("truncated netlink message (len=%d remaining=%d)", nlen, len(remaining))
		}
		typ := binary.LittleEndian.Uint16(remaining[4:6])
		payload := remaining[nlmsgHdrLen:nlen]
		switch typ {
		case rtmNewRoute:
			msg, err := parseNewRoute(payload)
			if err != nil {
				return RouteReply{}, err
			}
			msg.Type = rtmNewRoute
			messages = append(messages, msg)
		case nlmsgError:
			if len(payload) < 4 {
				return RouteReply{}, fmt.Errorf("truncated NLMSG_ERROR")
			}
			errno := -int(int32(binary.LittleEndian.Uint32(payload[0:4])))
			if errno != 0 {
				return RouteReply{
					Evidence: fmt.Sprintf("NLMSG_ERROR errno %d (%d bytes)", errno, len(buf)),
				}, netlinkErrno{Errno: errno}
			}
		case nlmsgDone:
			return RouteReply{
				Messages: messages,
				Evidence: fmt.Sprintf("%d RTM_NEWROUTE in %d bytes", len(messages), len(buf)),
			}, nil
		}
		aligned := nlmsgAlign(nlen)
		if aligned > len(remaining) {
			break
		}
		remaining = remaining[aligned:]
	}
	return RouteReply{
		Messages: messages,
		Evidence: fmt.Sprintf("%d RTM_NEWROUTE in %d bytes", len(messages), len(buf)),
	}, nil
}

func parseNewRoute(payload []byte) (RouteMessage, error) {
	if len(payload) < rtmsgLen {
		return RouteMessage{}, fmt.Errorf("short RTM_NEWROUTE")
	}
	msg := RouteMessage{
		Family: payload[0],
		Table:  payload[4],
	}
	attrs := payload[rtmsgLen:]
	for len(attrs) >= rtattrHdrLen {
		alen := int(binary.LittleEndian.Uint16(attrs[0:2]))
		atype := binary.LittleEndian.Uint16(attrs[2:4])
		if alen < rtattrHdrLen || alen > len(attrs) {
			return RouteMessage{}, fmt.Errorf("truncated rtattr")
		}
		val := attrs[rtattrHdrLen:alen]
		switch atype {
		case rtaPrefSrc:
			addr, err := addrFromFamily(int(msg.Family), val)
			if err != nil {
				return RouteMessage{}, err
			}
			msg.PrefSrc = addr.Unmap()
			msg.HasPrefSrc = true
		case rtaOif:
			if len(val) < 4 {
				return RouteMessage{}, fmt.Errorf("short RTA_OIF")
			}
			msg.OutIfIndex = int(binary.LittleEndian.Uint32(val[:4]))
			msg.HasOutIf = true
		}
		aligned := nlmsgAlign(alen)
		if aligned > len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	return msg, nil
}

func countNewRoute(reply RouteReply) int {
	n := 0
	for _, msg := range reply.Messages {
		if msg.Type == rtmNewRoute || msg.Type == 0 {
			n++
		}
	}
	return n
}
