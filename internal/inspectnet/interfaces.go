package inspectnet

import (
	"net"
	"net/netip"
)

// Interface is one guest NIC used as a fixture or from net.Interfaces.
type Interface struct {
	Index int
	Name  string
	Flags net.Flags
	Addrs []netip.Addr
}

// ListHostInterfaces snapshots net.Interfaces. Names are diagnostic hints.
func ListHostInterfaces() ([]Interface, error) {
	raw, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(raw))
	for _, iface := range raw {
		info := Interface{
			Index: iface.Index,
			Name:  iface.Name,
			Flags: iface.Flags,
		}
		addrs, err := iface.Addrs()
		if err != nil {
			out = append(out, info)
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil {
				continue
			}
			parsed, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			info.Addrs = append(info.Addrs, parsed.Unmap())
		}
		out = append(out, info)
	}
	return out, nil
}

func ifaceByIndex(ifaces []Interface, index int) (Interface, bool) {
	for _, iface := range ifaces {
		if iface.Index == index {
			return iface, true
		}
	}
	return Interface{}, false
}

func familyUnicast(iface Interface, family int) []netip.Addr {
	var out []netip.Addr
	for _, addr := range iface.Addrs {
		addr = addr.Unmap()
		if !usableFamilyAddr(addr, family) {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func usableFamilyAddr(addr netip.Addr, family int) bool {
	if !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	if family == FamilyIPv4 {
		return addr.Is4()
	}
	if family == FamilyIPv6 {
		return addr.Is6()
	}
	return false
}

func linkLocalOnly(iface Interface, family int) bool {
	hasFamily := false
	for _, addr := range iface.Addrs {
		addr = addr.Unmap()
		if family == FamilyIPv4 && !addr.Is4() {
			continue
		}
		if family == FamilyIPv6 && !addr.Is6() {
			continue
		}
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		hasFamily = true
		if !addr.IsLinkLocalUnicast() && !addr.IsLoopback() {
			return false
		}
	}
	return hasFamily
}
