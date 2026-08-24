package inspectnet

import (
	"fmt"
	"net"
	"net/netip"
)

// RouteLookup issues one RTM_GETROUTE lookup. Tests inject fakes; production
// uses KernelRouteLookup.
type RouteLookup func(family int, dst netip.Addr) (RouteReply, error)

type familyCandidate struct {
	Addr  netip.Addr
	Iface Interface
	ok    bool
}

// Discover selects at most one bind address from the main-table default-route
// source of each family. Zero usable candidates return an invalid address
// (the caller falls back to 127.0.0.1). Both families unique fail closed and
// name --listen.
func Discover(lookup RouteLookup, ifaces []Interface) (netip.Addr, error) {
	if lookup == nil {
		return netip.Addr{}, fmt.Errorf("inspect-network: route lookup is required; pass --listen")
	}
	v4, err := candidateForFamily(lookup, ifaces, FamilyIPv4, ProbeIPv4)
	if err != nil {
		return netip.Addr{}, err
	}
	v6, err := candidateForFamily(lookup, ifaces, FamilyIPv6, ProbeIPv6)
	if err != nil {
		return netip.Addr{}, err
	}
	switch {
	case v4.ok && v6.ok:
		return netip.Addr{}, fmt.Errorf(
			"inspect-network: both IPv4 %s (%s) and IPv6 %s (%s) are unique default-route sources; pass --listen",
			v4.Addr, v4.Iface.Name, v6.Addr, v6.Iface.Name,
		)
	case v4.ok:
		return v4.Addr, nil
	case v6.ok:
		return v6.Addr, nil
	default:
		return netip.Addr{}, nil
	}
}

func candidateForFamily(lookup RouteLookup, ifaces []Interface, family int, probe netip.Addr) (familyCandidate, error) {
	reply, err := lookup(family, probe)
	if err != nil {
		var nlErr netlinkErrno
		if asNetlinkErrno(err, &nlErr) && nlErr.unreachable() {
			return familyCandidate{}, nil
		}
		return familyCandidate{}, err
	}
	n := countNewRoute(reply)
	if n != 1 {
		if n == 0 {
			return familyCandidate{}, nil
		}
		return familyCandidate{}, fmt.Errorf(
			"inspect-network: RTM_GETROUTE lookup returned %d RTM_NEWROUTE messages, want exactly 1; pass --listen (%s)",
			n, reply.Evidence,
		)
	}
	route := reply.Messages[0]
	var addr netip.Addr
	var iface Interface
	var haveIface bool
	if route.HasOutIf {
		iface, haveIface = ifaceByIndex(ifaces, route.OutIfIndex)
	}
	if route.HasPrefSrc {
		addr = route.PrefSrc.Unmap()
	} else {
		if !haveIface {
			return familyCandidate{}, fmt.Errorf(
				"inspect-network: RTM_NEWROUTE has no RTA_PREFSRC and RTA_OIF %d is missing; pass --listen (%s)",
				route.OutIfIndex, reply.Evidence,
			)
		}
		addrs := familyUnicast(iface, family)
		if len(addrs) != 1 {
			return familyCandidate{}, fmt.Errorf(
				"inspect-network: interface %s (index %d) has %d unicast addresses of this family after PREFSRC-absent lookup, want 1; pass --listen (%s)",
				iface.Name, iface.Index, len(addrs), reply.Evidence,
			)
		}
		addr = addrs[0]
	}
	if !haveIface {
		return familyCandidate{}, fmt.Errorf(
			"inspect-network: cannot resolve output interface for %s; pass --listen (%s)",
			addr, reply.Evidence,
		)
	}
	return filterCandidate(iface, addr, family)
}

func filterCandidate(iface Interface, addr netip.Addr, family int) (familyCandidate, error) {
	addr = addr.Unmap()
	if iface.Flags&net.FlagUp == 0 {
		return familyCandidate{}, nil
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return familyCandidate{}, nil
	}
	if linkLocalOnly(iface, family) {
		return familyCandidate{}, nil
	}
	if !usableFamilyAddr(addr, family) {
		return familyCandidate{}, nil
	}
	return familyCandidate{Addr: addr, Iface: iface, ok: true}, nil
}

func asNetlinkErrno(err error, target *netlinkErrno) bool {
	if err == nil {
		return false
	}
	nl, ok := err.(netlinkErrno)
	if !ok {
		return false
	}
	*target = nl
	return true
}
