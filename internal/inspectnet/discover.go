package inspectnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
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
// source of each family. Both unique families fail closed and name --listen.
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
	route, ok := singleNewRoute(reply)
	if !ok {
		return familyCandidate{}, fmt.Errorf(
			"inspect-network: RTM_GETROUTE lookup returned %d RTM_NEWROUTE messages, want exactly 1; pass --listen (%s)",
			n, reply.Evidence,
		)
	}
	if route.Table != uint32(rtTableMain) {
		return familyCandidate{}, fmt.Errorf(
			"inspect-network: RTM_GETROUTE selected table %d, want RT_TABLE_MAIN (%d); prefsrc %s oif %d; pass --listen (%s)",
			route.Table, rtTableMain, route.PrefSrc, route.OutIfIndex, reply.Evidence,
		)
	}
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

// AddressForInterface resolves one named guest interface to a single unicast
// address. The name is a bind source, not a persisted locator. Zero or several
// usable addresses fail closed and name --listen.
func AddressForInterface(name string, ifaces []Interface) (netip.Addr, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return netip.Addr{}, fmt.Errorf("listen-interface is empty; pass --listen")
	}
	var found *Interface
	for i := range ifaces {
		if ifaces[i].Name == name {
			found = &ifaces[i]
			break
		}
	}
	if found == nil {
		return netip.Addr{}, fmt.Errorf("listen-interface %s was not found; pass --listen", name)
	}
	if found.Flags&net.FlagUp == 0 {
		return netip.Addr{}, fmt.Errorf("listen-interface %s is down; pass --listen", name)
	}
	if found.Flags&net.FlagLoopback != 0 {
		return netip.Addr{}, fmt.Errorf("listen-interface %s is loopback; pass --listen", name)
	}
	v4 := familyUnicast(*found, FamilyIPv4)
	v6 := familyUnicast(*found, FamilyIPv6)
	switch {
	case len(v4) == 1 && len(v6) == 1:
		return netip.Addr{}, fmt.Errorf(
			"listen-interface %s has unique IPv4 %s and IPv6 %s; pass --listen",
			name, v4[0], v6[0],
		)
	case len(v4) == 1 && len(v6) == 0:
		return v4[0], nil
	case len(v6) == 1 && len(v4) == 0:
		return v6[0], nil
	case len(v4) > 1:
		return netip.Addr{}, fmt.Errorf("listen-interface %s has %d IPv4 addresses, want 1; pass --listen", name, len(v4))
	case len(v6) > 1:
		return netip.Addr{}, fmt.Errorf("listen-interface %s has %d IPv6 addresses, want 1; pass --listen", name, len(v6))
	default:
		return netip.Addr{}, fmt.Errorf("listen-interface %s has no usable unicast address; pass --listen", name)
	}
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
	return errors.As(err, target)
}
