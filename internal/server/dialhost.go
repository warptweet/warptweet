package server

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	maxDNSNameOctets  = 253
	maxDNSLabelOctets = 63
)

// DialHost is a locator: a canonical IP literal or a DNS name.
// It is not an authentication authority. JSON is a single host string.
type DialHost struct {
	IP   netip.Addr // set XOR Name
	Name string     // absolute DNS, JSON without trailing dot
}

// IPDialHost stores an unmapped IP locator.
func IPDialHost(addr netip.Addr) DialHost {
	return DialHost{IP: canonicalAddress(addr)}
}

// ParseDialHost parses one IP literal or DNS name into a DialHost.
func ParseDialHost(value string) (DialHost, error) {
	if value == "" {
		return DialHost{}, fmt.Errorf("dial host is empty")
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Zone() != "" {
			return DialHost{}, fmt.Errorf("IPv6 zones are not permitted")
		}
		return IPDialHost(addr), nil
	}
	name, err := CanonicalDNSName(value)
	if err != nil {
		return DialHost{}, err
	}
	return DialHost{Name: name}, nil
}

// Canonical returns the lowercase A-label or unmapped IP string used for
// equality, JSON, and published-set comparison.
func (host DialHost) Canonical() (string, error) {
	hasIP := host.IP.IsValid()
	hasName := host.Name != ""
	switch {
	case hasIP && hasName:
		return "", fmt.Errorf("dial host must not set both IP and Name")
	case hasIP:
		if host.IP.Zone() != "" {
			return "", fmt.Errorf("IPv6 zones are not permitted")
		}
		return canonicalAddress(host.IP).String(), nil
	case hasName:
		return CanonicalDNSName(host.Name)
	default:
		return "", fmt.Errorf("dial host is empty")
	}
}

// Equal reports canonical locator equality.
func (host DialHost) Equal(other DialHost) bool {
	left, leftErr := host.Canonical()
	right, rightErr := other.Canonical()
	return leftErr == nil && rightErr == nil && left == right
}

// MarshalJSON encodes DialHost as a JSON string.
func (host DialHost) MarshalJSON() ([]byte, error) {
	canonical, err := host.Canonical()
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

// UnmarshalJSON decodes a JSON string into the IP or DNS arm.
func (host *DialHost) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("dial host must be a string")
	}
	parsed, err := ParseDialHost(value)
	if err != nil {
		return err
	}
	*host = parsed
	return nil
}

// CanonicalDNSName lowercases an ASCII A-label name and strips one trailing
// dot. TUNNEL.EXAMPLE.COM and tunnel.example.com are the same result.
func CanonicalDNSName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("DNS name is empty")
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("DNS name is not valid UTF-8")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Errorf("DNS name must not be an IP literal")
	}
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
		if name == "" {
			return "", fmt.Errorf("DNS name is empty")
		}
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("DNS name contains an empty label")
	}
	for _, r := range name {
		if r > 127 {
			return "", fmt.Errorf("DNS name must be ASCII A-labels")
		}
		if r < 0x20 || r == 0x7f || r == ' ' || strings.ContainsRune("/?#@:[]*%", r) {
			return "", fmt.Errorf("DNS name contains a forbidden character")
		}
	}
	lower := strings.ToLower(name)
	if len(lower) > maxDNSNameOctets {
		return "", fmt.Errorf("DNS name exceeds %d octets", maxDNSNameOctets)
	}
	labels := strings.Split(lower, ".")
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("DNS name contains an empty label")
		}
		if len(label) > maxDNSLabelOctets {
			return "", fmt.Errorf("DNS label exceeds %d octets", maxDNSLabelOctets)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("DNS label must not start or end with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return "", fmt.Errorf("DNS name contains a forbidden character")
		}
	}
	return lower, nil
}
