package inspectnet

import "net/netip"

// Linux rtnetlink constants, duplicated so Darwin tests compile without
// golang.org/x/sys/unix netlink symbols. Linux tests assert they match the kernel.
const (
	nlmsgAlignTo = 4
	nlmsgHdrLen  = 16
	rtmsgLen     = 12
	rtattrHdrLen = 4

	nlFRequest = 0x1
	nlFDump    = 0x300

	rtmNewRoute = 24
	rtmGetRoute = 26
	nlmsgError  = 0x2
	nlmsgDone   = 0x3

	FamilyIPv4 = 2
	FamilyIPv6 = 10

	rtaDst     = 1
	rtaOif     = 4
	rtaPrefSrc = 7
	rtaTable   = 0xf

	rtTableMain = 254

	errnoNetUnreach  = 101
	errnoHostUnreach = 113
	errnoNetDown     = 100
)

// Documentation prefixes used as RTM_GETROUTE destinations. This is a route
// lookup, not a reachability probe.
var (
	ProbeIPv4 = netip.MustParseAddr("192.0.2.1")
	ProbeIPv6 = netip.MustParseAddr("2001:db8::1")
)

func nlmsgAlign(n int) int {
	return (n + nlmsgAlignTo - 1) &^ (nlmsgAlignTo - 1)
}
