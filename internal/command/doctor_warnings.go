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
	warnings = append(warnings, servicePublicationWarnings(
		"data",
		"private_dial_equals_bind",
		"nonglobal_bind_raw_ip_dial",
		"cannot_create_inbound",
		manifest.Network.Data,
	)...)
	warnings = append(warnings, servicePublicationWarnings(
		"enrollment",
		"private_enrollment_dial_equals_bind",
		"nonglobal_enrollment_bind_raw_ip_dial",
		"cannot_create_enrollment_inbound",
		manifest.Network.Enrollment,
	)...)
	return warnings
}

func servicePublicationWarnings(
	label, privateCode, nonglobalCode, inboundCode string,
	endpoints server.ServiceEndpoints,
) []serverDoctorWarning {
	var warnings []serverDoctorWarning
	bind := canonicalDoctorAddr(endpoints.Listen.Address)
	dial := endpoints.Dial
	privateIPDial := false
	if dial.Host.IP.IsValid() {
		dialAddr := canonicalDoctorAddr(dial.Host.IP)
		privateIPDial = isPrivateOrCGNAT(dialAddr)
		if privateIPDial && dialAddr == bind && !bind.IsLoopback() {
			warnings = append(warnings, serverDoctorWarning{
				Code:    privateCode,
				Message: "published " + label + " dial equals a private bind; this is a VPC-only locator, not a public published endpoint",
			})
		}
		if !isPubliclyRoutable(bind) && !bind.IsLoopback() {
			warnings = append(warnings, serverDoctorWarning{
				Code:    nonglobalCode,
				Message: label + " bind is not globally routable and " + label + " dial is a raw IP; clients must be able to reach that locator",
			})
		}
	}
	if !isPubliclyRoutable(bind) && !bind.IsLoopback() {
		message := "WarpTweet cannot create inbound mappings"
		if privateIPDial {
			message += "; outbound-only NAT is unsupported"
		}
		warnings = append(warnings, serverDoctorWarning{
			Code:    inboundCode,
			Message: message,
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
