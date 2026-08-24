package command

import (
	"net/netip"

	"warptweet.com/warptweet/internal/server"
)

type serverDoctorWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func publicationWarnings(manifest server.Config) []serverDoctorWarning {
	var warnings []serverDoctorWarning
	dataBind := canonicalDoctorAddr(manifest.Network.Data.Listen.Address)
	dataDial := manifest.Network.Data.Dial
	if dataDial.Host.IP.IsValid() {
		dialAddr := canonicalDoctorAddr(dataDial.Host.IP)
		if isPrivateOrCGNAT(dialAddr) && dialAddr == dataBind && !dataBind.IsLoopback() {
			warnings = append(warnings, serverDoctorWarning{
				Code:    "private_dial_equals_bind",
				Message: "published data dial equals a private bind; this is a VPC-only locator, not a public pin",
			})
		}
		if !isPubliclyRoutable(dataBind) && !dataBind.IsLoopback() {
			warnings = append(warnings, serverDoctorWarning{
				Code:    "nonglobal_bind_raw_ip_dial",
				Message: "data bind is not globally routable and data dial is a raw IP; clients must be able to reach that locator",
			})
		}
	}
	if !isPubliclyRoutable(dataBind) && !dataBind.IsLoopback() {
		warnings = append(warnings, serverDoctorWarning{
			Code:    "cannot_create_inbound",
			Message: "WarpTweet cannot create inbound mappings; outbound-only NAT is unsupported",
		})
	}
	return warnings
}

func canonicalDoctorAddr(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}
	return addr.Unmap()
}

func isPubliclyRoutable(addr netip.Addr) bool {
	addr = canonicalDoctorAddr(addr)
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() || isCGNAT(addr) {
		return false
	}
	return addr.IsGlobalUnicast()
}

func isPrivateOrCGNAT(addr netip.Addr) bool {
	addr = canonicalDoctorAddr(addr)
	return addr.IsValid() && (addr.IsPrivate() || isCGNAT(addr))
}

func isCGNAT(addr netip.Addr) bool {
	return addr.Is4() && cgnatPrefix.Contains(addr)
}
