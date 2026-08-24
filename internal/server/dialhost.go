package server

import (
	"net/netip"

	"warptweet.com/warptweet/internal/locator"
)

// DialHost is a locator: a canonical IP literal or a DNS name.
// Canonicalization lives in locator so invite, client manifests, and
// parseHostForURL share one function.
type DialHost = locator.DialHost

// IPDialHost stores an unmapped IP locator.
func IPDialHost(addr netip.Addr) DialHost {
	return locator.IPDialHost(addr)
}

// ParseDialHost parses one IP literal or DNS name into a DialHost.
func ParseDialHost(value string) (DialHost, error) {
	return locator.ParseDialHost(value)
}

// CanonicalDNSName lowercases an ASCII A-label name and strips one trailing
// dot. TUNNEL.EXAMPLE.COM and tunnel.example.com are the same result.
func CanonicalDNSName(name string) (string, error) {
	return locator.CanonicalDNSName(name)
}
