package inspectnet

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestBuildGetRouteLookupIsLookupNotDump(t *testing.T) {
	t.Parallel()

	v4, err := BuildGetRouteLookup(FamilyIPv4, ProbeIPv4)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseGetRouteRequest(v4)
	if err != nil {
		t.Fatal(err)
	}
	if req.HasDump {
		t.Fatal("IPv4 lookup set NLM_F_DUMP")
	}
	if req.Flags&nlFRequest == 0 {
		t.Fatal("IPv4 lookup missing NLM_F_REQUEST")
	}
	if req.DstLen != 32 || req.Table != rtTableMain || req.Dst != ProbeIPv4 {
		t.Fatalf("IPv4 lookup request = %+v", req)
	}

	v6, err := BuildGetRouteLookup(FamilyIPv6, ProbeIPv6)
	if err != nil {
		t.Fatal(err)
	}
	req6, err := ParseGetRouteRequest(v6)
	if err != nil {
		t.Fatal(err)
	}
	if req6.HasDump || req6.DstLen != 128 || req6.Dst != ProbeIPv6 || req6.Table != rtTableMain {
		t.Fatalf("IPv6 lookup request = %+v", req6)
	}

	dump := append([]byte(nil), v4...)
	dump[6] = byte((nlFRequest | nlFDump) & 0xff)
	dump[7] = byte((nlFRequest | nlFDump) >> 8)
	parsedDump, err := ParseGetRouteRequest(dump)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedDump.HasDump {
		t.Fatal("dump-flagged request did not parse as dump")
	}
}

func TestDiscoverLookupVsDumpResponse(t *testing.T) {
	t.Parallel()

	ifaces := []Interface{{
		Index: 2,
		Name:  "ens4",
		Flags: net.FlagUp,
		Addrs: []netip.Addr{netip.MustParseAddr("10.168.0.2")},
	}}
	one := RouteReply{
		Messages: []RouteMessage{{
			Type:       rtmNewRoute,
			Family:     FamilyIPv4,
			Table:      uint32(rtTableMain),
			HasPrefSrc: true,
			PrefSrc:    netip.MustParseAddr("10.168.0.2"),
			HasOutIf:   true,
			OutIfIndex: 2,
		}},
		Evidence: "1 RTM_NEWROUTE",
	}
	addr, err := Discover(fixedLookup(one, RouteReply{}), ifaces)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "10.168.0.2" {
		t.Fatalf("addr = %s", addr)
	}

	dump := RouteReply{
		Messages: []RouteMessage{
			{Type: rtmNewRoute, Family: FamilyIPv4, HasPrefSrc: true, PrefSrc: netip.MustParseAddr("10.168.0.2"), HasOutIf: true, OutIfIndex: 2},
			{Type: rtmNewRoute, Family: FamilyIPv4, HasPrefSrc: true, PrefSrc: netip.MustParseAddr("172.17.0.1"), HasOutIf: true, OutIfIndex: 3},
		},
		Evidence: "2 RTM_NEWROUTE dump",
	}
	_, err = Discover(fixedLookup(dump, RouteReply{}), ifaces)
	if err == nil || !strings.Contains(err.Error(), "--listen") || !strings.Contains(err.Error(), "2 RTM_NEWROUTE") {
		t.Fatalf("dump-shaped reply error = %v", err)
	}
}

func TestDiscoverPrefSrcAbsentInterfaceAddressCardinality(t *testing.T) {
	t.Parallel()

	lookup := func(family int, dst netip.Addr) (RouteReply, error) {
		if family != FamilyIPv4 {
			return RouteReply{}, nil
		}
		return RouteReply{
			Messages: []RouteMessage{{
				Type:       rtmNewRoute,
				Family:     FamilyIPv4,
				Table:      uint32(rtTableMain),
				HasOutIf:   true,
				OutIfIndex: 2,
			}},
			Evidence: "PREFSRC absent",
		}, nil
	}

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		ifaces := []Interface{{Index: 2, Name: "ens4", Flags: net.FlagUp}}
		_, err := Discover(lookup, ifaces)
		if err == nil || !strings.Contains(err.Error(), "0 unicast") || !strings.Contains(err.Error(), "--listen") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("one", func(t *testing.T) {
		t.Parallel()
		ifaces := []Interface{{
			Index: 2,
			Name:  "ens4",
			Flags: net.FlagUp,
			Addrs: []netip.Addr{
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("10.168.0.2"),
			},
		}}
		addr, err := Discover(lookup, ifaces)
		if err != nil {
			t.Fatal(err)
		}
		if addr.String() != "10.168.0.2" {
			t.Fatalf("addr = %s", addr)
		}
	})
	t.Run("several", func(t *testing.T) {
		t.Parallel()
		ifaces := []Interface{{
			Index: 2,
			Name:  "ens4",
			Flags: net.FlagUp,
			Addrs: []netip.Addr{
				netip.MustParseAddr("10.168.0.2"),
				netip.MustParseAddr("10.168.0.3"),
			},
		}}
		_, err := Discover(lookup, ifaces)
		if err == nil || !strings.Contains(err.Error(), "2 unicast") || !strings.Contains(err.Error(), "--listen") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestDiscoverBothFamiliesUniqueFailsClosed(t *testing.T) {
	t.Parallel()

	ifaces := []Interface{
		{
			Index: 2,
			Name:  "ens4",
			Flags: net.FlagUp,
			Addrs: []netip.Addr{
				netip.MustParseAddr("10.168.0.2"),
				netip.MustParseAddr("2001:db8::10"),
			},
		},
	}
	lookup := func(family int, dst netip.Addr) (RouteReply, error) {
		msg := RouteMessage{Type: rtmNewRoute, Family: uint8(family), Table: uint32(rtTableMain), HasOutIf: true, OutIfIndex: 2, HasPrefSrc: true}
		if family == FamilyIPv4 {
			msg.PrefSrc = netip.MustParseAddr("10.168.0.2")
		} else {
			msg.PrefSrc = netip.MustParseAddr("2001:db8::10")
		}
		return RouteReply{Messages: []RouteMessage{msg}, Evidence: "one"}, nil
	}
	_, err := Discover(lookup, ifaces)
	if err == nil || !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "10.168.0.2") || !strings.Contains(err.Error(), "2001:db8::10") {
		t.Fatalf("error did not print both candidates: %v", err)
	}
}

func TestDiscoverExtraTableFailsClosed(t *testing.T) {
	t.Parallel()

	ifaces := []Interface{{
		Index: 2,
		Name:  "ens4",
		Flags: net.FlagUp,
		Addrs: []netip.Addr{netip.MustParseAddr("10.168.0.2")},
	}}
	lookup := func(family int, dst netip.Addr) (RouteReply, error) {
		if family != FamilyIPv4 {
			return RouteReply{}, nil
		}
		return RouteReply{
			Messages: []RouteMessage{{
				Type:       rtmNewRoute,
				Family:     FamilyIPv4,
				Table:      100,
				HasPrefSrc: true,
				PrefSrc:    netip.MustParseAddr("10.168.0.2"),
				HasOutIf:   true,
				OutIfIndex: 2,
			}},
			Evidence: "table 100",
		}, nil
	}
	_, err := Discover(lookup, ifaces)
	if err == nil || !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "table 100") || !strings.Contains(err.Error(), "10.168.0.2") {
		t.Fatalf("error missing kernel evidence: %v", err)
	}
}

func TestDiscoverZeroCandidatesReturnsInvalidAddr(t *testing.T) {
	t.Parallel()

	addr, err := Discover(func(int, netip.Addr) (RouteReply, error) {
		return RouteReply{}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr.IsValid() {
		t.Fatalf("addr = %s, want invalid", addr)
	}
}

func TestDiscoverIgnoresInterfaceNameAsExclusionAuthority(t *testing.T) {
	t.Parallel()

	ifaces := []Interface{{
		Index: 3,
		Name:  "docker0",
		Flags: net.FlagUp,
		Addrs: []netip.Addr{netip.MustParseAddr("172.17.0.1")},
	}}
	lookup := func(family int, dst netip.Addr) (RouteReply, error) {
		if family != FamilyIPv4 {
			return RouteReply{}, nil
		}
		return RouteReply{Messages: []RouteMessage{{
			Type:       rtmNewRoute,
			Table:      uint32(rtTableMain),
			HasPrefSrc: true,
			PrefSrc:    netip.MustParseAddr("172.17.0.1"),
			HasOutIf:   true,
			OutIfIndex: 3,
		}}}, nil
	}
	addr, err := Discover(lookup, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "172.17.0.1" {
		t.Fatalf("docker0 name excluded the kernel-selected source: %s", addr)
	}
}

func TestDiscoverExcludesLoopbackDownAndLinkLocalOnly(t *testing.T) {
	t.Parallel()

	ifaces := []Interface{{
		Index: 1,
		Name:  "lo",
		Flags: net.FlagUp | net.FlagLoopback,
		Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}}
	lookup := func(family int, dst netip.Addr) (RouteReply, error) {
		if family != FamilyIPv4 {
			return RouteReply{}, nil
		}
		return RouteReply{Messages: []RouteMessage{{
			Type:       rtmNewRoute,
			Table:      uint32(rtTableMain),
			HasPrefSrc: true,
			PrefSrc:    netip.MustParseAddr("127.0.0.1"),
			HasOutIf:   true,
			OutIfIndex: 1,
		}}}, nil
	}
	addr, err := Discover(lookup, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	if addr.IsValid() {
		t.Fatalf("loopback candidate leaked: %s", addr)
	}
}

func TestFamilyUnicastSkipsLinkLocalWhenCounting(t *testing.T) {
	t.Parallel()

	iface := Interface{
		Index: 2,
		Name:  "ens4",
		Flags: net.FlagUp,
		Addrs: []netip.Addr{
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("10.168.0.2"),
		},
	}
	got := familyUnicast(iface, FamilyIPv4)
	if len(got) != 1 || got[0].String() != "10.168.0.2" {
		t.Fatalf("got %v", got)
	}
}

func fixedLookup(v4, v6 RouteReply) RouteLookup {
	return func(family int, dst netip.Addr) (RouteReply, error) {
		_ = dst
		if family == FamilyIPv4 {
			return v4, nil
		}
		return v6, nil
	}
}
