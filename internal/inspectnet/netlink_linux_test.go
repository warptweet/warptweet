//go:build linux

package inspectnet

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxNetlinkConstantsMatchKernel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  int
		want int
	}{
		{"NLM_F_REQUEST", nlFRequest, int(unix.NLM_F_REQUEST)},
		{"NLM_F_DUMP", nlFDump, int(unix.NLM_F_DUMP)},
		{"RTM_GETROUTE", rtmGetRoute, int(unix.RTM_GETROUTE)},
		{"RTM_NEWROUTE", rtmNewRoute, int(unix.RTM_NEWROUTE)},
		{"AF_INET", FamilyIPv4, int(unix.AF_INET)},
		{"AF_INET6", FamilyIPv6, int(unix.AF_INET6)},
		{"RTA_DST", rtaDst, int(unix.RTA_DST)},
		{"RTA_OIF", rtaOif, int(unix.RTA_OIF)},
		{"RTA_PREFSRC", rtaPrefSrc, int(unix.RTA_PREFSRC)},
		{"RT_TABLE_MAIN", rtTableMain, int(unix.RT_TABLE_MAIN)},
	}
	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("%s = %d, want %d", test.name, test.got, test.want)
		}
	}
}

func TestLinuxLookupCardinality(t *testing.T) {
	lookup, err := KernelRouteLookup(FamilyIPv4, ProbeIPv4)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	lookupN := countNewRoute(lookup)
	if lookupN > 1 {
		t.Fatalf("RTM_GETROUTE lookup returned %d RTM_NEWROUTE; lookup must not dump (%s)", lookupN, lookup.Evidence)
	}

	dump, err := dumpGetRoute(FamilyIPv4)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	dumpN := countNewRoute(dump)
	if dumpN > 1 && lookupN == dumpN {
		t.Fatalf("lookup cardinality %d matched dump %d; lookup used dump semantics (lookup %s dump %s)", lookupN, dumpN, lookup.Evidence, dump.Evidence)
	}
	if lookupN > dumpN && dumpN > 0 {
		t.Fatalf("lookup returned more RTM_NEWROUTE (%d) than dump (%d)", lookupN, dumpN)
	}
}

func dumpGetRoute(family int) (RouteReply, error) {
	dst := ProbeIPv4
	if family == FamilyIPv6 {
		dst = ProbeIPv6
	}
	req, err := BuildGetRouteLookup(family, dst)
	if err != nil {
		return RouteReply{}, err
	}
	req[nlmsgHdrLen+1] = 0
	binary.LittleEndian.PutUint16(req[6:8], nlFRequest|nlFDump)
	binary.LittleEndian.PutUint32(req[0:4], uint32(nlmsgHdrLen+rtmsgLen))
	req = req[:nlmsgHdrLen+rtmsgLen]

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return RouteReply{}, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return RouteReply{}, err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return RouteReply{}, err
	}
	local := sa.(*unix.SockaddrNetlink)
	binary.LittleEndian.PutUint32(req[12:16], local.Pid)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return RouteReply{}, err
	}

	var assembled []byte
	buf := make([]byte, 64<<10)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return RouteReply{}, err
		}
		assembled = append(assembled, buf[:n]...)
		if containsDone(assembled) {
			return ParseRouteMessages(assembled)
		}
		if n == 0 {
			break
		}
	}
	return ParseRouteMessages(assembled)
}

func containsDone(buf []byte) bool {
	remaining := buf
	for len(remaining) >= nlmsgHdrLen {
		nlen := int(binary.LittleEndian.Uint32(remaining[0:4]))
		if nlen < nlmsgHdrLen || nlen > len(remaining) {
			return false
		}
		if binary.LittleEndian.Uint16(remaining[4:6]) == nlmsgDone {
			return true
		}
		aligned := nlmsgAlign(nlen)
		if aligned > len(remaining) {
			return false
		}
		remaining = remaining[aligned:]
	}
	return false
}
