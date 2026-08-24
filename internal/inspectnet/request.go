package inspectnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// BuildGetRouteLookup encodes RTM_GETROUTE with NLM_F_REQUEST, without
// NLM_F_DUMP, rtm_dst_len 32 or 128, RTA_DST, and RT_TABLE_MAIN.
func BuildGetRouteLookup(family int, dst netip.Addr) ([]byte, error) {
	dst = dst.Unmap()
	var dstLen uint8
	var dstBytes []byte
	switch family {
	case FamilyIPv4:
		if !dst.Is4() {
			return nil, fmt.Errorf("IPv4 route lookup requires an IPv4 destination")
		}
		dstLen = 32
		b := dst.As4()
		dstBytes = b[:]
	case FamilyIPv6:
		if !dst.Is6() {
			return nil, fmt.Errorf("IPv6 route lookup requires an IPv6 destination")
		}
		dstLen = 128
		b := dst.As16()
		dstBytes = b[:]
	default:
		return nil, fmt.Errorf("unsupported route lookup family %d", family)
	}

	rtaLen := rtattrHdrLen + len(dstBytes)
	alignedRTA := nlmsgAlign(rtaLen)
	total := nlmsgHdrLen + rtmsgLen + alignedRTA
	buf := make([]byte, total)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], rtmGetRoute)
	binary.LittleEndian.PutUint16(buf[6:8], nlFRequest)
	binary.LittleEndian.PutUint32(buf[8:12], 1)

	buf[nlmsgHdrLen] = uint8(family)
	buf[nlmsgHdrLen+1] = dstLen
	buf[nlmsgHdrLen+4] = rtTableMain

	rtaOff := nlmsgHdrLen + rtmsgLen
	binary.LittleEndian.PutUint16(buf[rtaOff:rtaOff+2], uint16(rtaLen))
	binary.LittleEndian.PutUint16(buf[rtaOff+2:rtaOff+4], rtaDst)
	copy(buf[rtaOff+4:], dstBytes)
	return buf, nil
}

// LookupRequest describes a decoded RTM_GETROUTE request. Tests use it to
// distinguish lookup from dump.
type LookupRequest struct {
	Family  int
	Flags   uint16
	DstLen  uint8
	Table   uint8
	Dst     netip.Addr
	HasDump bool
}

// ParseGetRouteRequest decodes a request built by BuildGetRouteLookup.
func ParseGetRouteRequest(buf []byte) (LookupRequest, error) {
	if len(buf) < nlmsgHdrLen+rtmsgLen+rtattrHdrLen {
		return LookupRequest{}, fmt.Errorf("short RTM_GETROUTE request")
	}
	nlen := int(binary.LittleEndian.Uint32(buf[0:4]))
	if nlen > len(buf) || nlen < nlmsgHdrLen+rtmsgLen {
		return LookupRequest{}, fmt.Errorf("invalid netlink length %d", nlen)
	}
	typ := binary.LittleEndian.Uint16(buf[4:6])
	if typ != rtmGetRoute {
		return LookupRequest{}, fmt.Errorf("nlmsg_type %d, want RTM_GETROUTE", typ)
	}
	flags := binary.LittleEndian.Uint16(buf[6:8])
	req := LookupRequest{
		Family:  int(buf[nlmsgHdrLen]),
		Flags:   flags,
		DstLen:  buf[nlmsgHdrLen+1],
		Table:   buf[nlmsgHdrLen+4],
		HasDump: flags&nlFDump != 0,
	}
	if flags&nlFRequest == 0 {
		return LookupRequest{}, fmt.Errorf("RTM_GETROUTE missing NLM_F_REQUEST")
	}
	attrs := buf[nlmsgHdrLen+rtmsgLen : nlen]
	for len(attrs) >= rtattrHdrLen {
		alen := int(binary.LittleEndian.Uint16(attrs[0:2]))
		atype := binary.LittleEndian.Uint16(attrs[2:4])
		if alen < rtattrHdrLen || alen > len(attrs) {
			return LookupRequest{}, fmt.Errorf("truncated request rtattr")
		}
		if atype == rtaDst {
			addr, err := addrFromFamily(req.Family, attrs[rtattrHdrLen:alen])
			if err != nil {
				return LookupRequest{}, err
			}
			req.Dst = addr
		}
		aligned := nlmsgAlign(alen)
		if aligned > len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	return req, nil
}

func addrFromFamily(family int, raw []byte) (netip.Addr, error) {
	switch family {
	case FamilyIPv4:
		if len(raw) < 4 {
			return netip.Addr{}, fmt.Errorf("short IPv4 attribute")
		}
		return netip.AddrFrom4([4]byte(raw[:4])), nil
	case FamilyIPv6:
		if len(raw) < 16 {
			return netip.Addr{}, fmt.Errorf("short IPv6 attribute")
		}
		return netip.AddrFrom16([16]byte(raw[:16])), nil
	default:
		return netip.Addr{}, fmt.Errorf("unsupported address family %d", family)
	}
}
