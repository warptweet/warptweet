package server

import (
	"fmt"
	"math"
	"net/netip"
)

// BindEndpoint is a concrete local socket. Address is always a numeric IP.
type BindEndpoint struct {
	Address netip.Addr `json:"address"`
	Port    Port       `json:"port"`
}

// DialEndpoint is a published locator. Host is an IP literal or DNS name.
type DialEndpoint struct {
	Host DialHost `json:"host"`
	Port Port     `json:"port"`
}

// ServiceEndpoints is one published service: local bind and client dial.
type ServiceEndpoints struct {
	Listen BindEndpoint `json:"listen"`
	Dial   DialEndpoint `json:"dial"`
}

// Network is the schema-2 bind/dial set. WarpTweet always writes every field.
type Network struct {
	PublishedEndpointGeneration uint64           `json:"published_endpoint_generation"`
	Data                        ServiceEndpoints `json:"data"`
	Enrollment                  ServiceEndpoints `json:"enrollment"`
}

// PublishedEndpointSet is the atomic published locator carried by invite,
// proof, receipts, and routes. JSON names the revision
// published_endpoint_generation; do not call it generation.
type PublishedEndpointSet struct {
	Generation uint64
	Data       DialEndpoint
	Enrollment DialEndpoint
}

// HostIdentity is enrollment SPKI and the SSH host key. It is not a locator.
type HostIdentity struct {
	EnrollmentSPKISHA256 string
	SSHHostKey           []byte
}

// PublicationNetwork publishes the bind addresses as IP locators and starts
// published_endpoint_generation at 1.
func PublicationNetwork(dataAddr netip.Addr, dataPort, enrollPort Port) Network {
	dataListen := BindEndpoint{Address: dataAddr, Port: dataPort}
	enrollListen := BindEndpoint{Address: dataAddr, Port: enrollPort}
	return Network{
		PublishedEndpointGeneration: 1,
		Data: ServiceEndpoints{
			Listen: dataListen,
			Dial:   dialFromBind(dataListen),
		},
		Enrollment: ServiceEndpoints{
			Listen: enrollListen,
			Dial:   dialFromBind(enrollListen),
		},
	}
}

// AddrPort is the canonical unmapped listen address and port.
func (endpoint BindEndpoint) AddrPort() netip.AddrPort {
	port := uint16(0)
	if endpoint.Port > 0 && endpoint.Port <= 65535 {
		port = uint16(endpoint.Port)
	}
	return netip.AddrPortFrom(canonicalAddress(endpoint.Address), port)
}

// PublishedSet returns the locator pair and its revision.
func (network Network) PublishedSet() PublishedEndpointSet {
	return PublishedEndpointSet{
		Generation: network.PublishedEndpointGeneration,
		Data:       network.Data.Dial,
		Enrollment: network.Enrollment.Dial,
	}
}

// SamePublishedLocators reports whether the canonical data and enrollment
// dials are equal. It ignores published_endpoint_generation.
func SamePublishedLocators(left, right PublishedEndpointSet) bool {
	return sameDialEndpoint(left.Data, right.Data) && sameDialEndpoint(left.Enrollment, right.Enrollment)
}

// ProposeNetwork builds the schema-2 network for one host invocation.
// Omitted advertise restores stored dials. Bind-only edits do not bump
// published_endpoint_generation. A locator change increments it once after
// the caller refuses live inventory and before the atomic manifest write.
func ProposeNetwork(dataListen, enrollListen BindEndpoint, stored *Network) (Network, bool, error) {
	dataDial := dialFromBind(dataListen)
	enrollDial := dialFromBind(enrollListen)
	generation := uint64(1)
	if stored != nil {
		dataDial = stored.Data.Dial
		enrollDial = stored.Enrollment.Dial
		generation = stored.PublishedEndpointGeneration
		if generation == 0 {
			generation = 1
		}
	}
	proposed := Network{
		PublishedEndpointGeneration: generation,
		Data: ServiceEndpoints{
			Listen: dataListen,
			Dial:   dataDial,
		},
		Enrollment: ServiceEndpoints{
			Listen: enrollListen,
			Dial:   enrollDial,
		},
	}
	if stored == nil {
		return proposed, false, nil
	}
	changed := !SamePublishedLocators(stored.PublishedSet(), proposed.PublishedSet())
	if !changed {
		return proposed, false, nil
	}
	next, err := nextPublishedEndpointGeneration(generation)
	if err != nil {
		return Network{}, true, err
	}
	proposed.PublishedEndpointGeneration = next
	return proposed, true, nil
}

func nextPublishedEndpointGeneration(current uint64) (uint64, error) {
	if current == math.MaxUint64 {
		return 0, invalidField(
			"Network.PublishedEndpointGeneration",
			"cannot increment past uint64 maximum",
		)
	}
	if current == 0 {
		return 1, nil
	}
	return current + 1, nil
}

func dialFromBind(listen BindEndpoint) DialEndpoint {
	return DialEndpoint{
		Host: IPDialHost(listen.Address),
		Port: listen.Port,
	}
}

func sameDialEndpoint(left, right DialEndpoint) bool {
	return left.Port == right.Port && left.Host.Equal(right.Host)
}

func bindLocatorKey(endpoint BindEndpoint) string {
	return canonicalAddress(endpoint.Address).String() + "\x00" + fmt.Sprintf("%d", endpoint.Port)
}

func dialLocatorKey(endpoint DialEndpoint) (string, error) {
	host, err := endpoint.Host.Canonical()
	if err != nil {
		return "", err
	}
	return host + "\x00" + fmt.Sprintf("%d", endpoint.Port), nil
}

func validateNetwork(network Network) error {
	if network.PublishedEndpointGeneration == 0 {
		return invalidField("Network.PublishedEndpointGeneration", "must be at least 1")
	}
	if err := validateBind("Network.Data.Listen", network.Data.Listen); err != nil {
		return err
	}
	if err := validateBind("Network.Enrollment.Listen", network.Enrollment.Listen); err != nil {
		return err
	}
	if bindLocatorKey(network.Data.Listen) == bindLocatorKey(network.Enrollment.Listen) {
		return invalidField(
			"Network",
			"data listen and enrollment listen must not share the same canonical address:port",
		)
	}
	if err := validateDial("Network.Data.Dial", network.Data.Listen, network.Data.Dial); err != nil {
		return err
	}
	if err := validateDial("Network.Enrollment.Dial", network.Enrollment.Listen, network.Enrollment.Dial); err != nil {
		return err
	}
	dataKey, err := dialLocatorKey(network.Data.Dial)
	if err != nil {
		return invalidField("Network.Data.Dial", "%v", err)
	}
	enrollKey, err := dialLocatorKey(network.Enrollment.Dial)
	if err != nil {
		return invalidField("Network.Enrollment.Dial", "%v", err)
	}
	if dataKey == enrollKey {
		return invalidField(
			"Network",
			"data dial and enrollment dial must not share the same canonical host:port",
		)
	}
	return nil
}

func validateBind(field string, endpoint BindEndpoint) error {
	return validateEndpoint(field, Endpoint{Address: endpoint.Address, Port: endpoint.Port})
}

func validateDial(field string, bind BindEndpoint, dial DialEndpoint) error {
	if dial.Port < 1 || dial.Port > 65535 {
		return invalidField(field+".Port", "must be between 1 and 65535")
	}
	hasIP := dial.Host.IP.IsValid()
	hasName := dial.Host.Name != ""
	if hasIP == hasName {
		return invalidField(field+".Host", "must be an IP literal or a DNS name")
	}
	bindAddr := canonicalAddress(bind.Address)
	if hasName {
		if _, err := CanonicalDNSName(dial.Host.Name); err != nil {
			return invalidField(field+".Host", "%v", err)
		}
		if bindAddr.IsLoopback() {
			return invalidField(field+".Host", "loopback bind cannot publish a non-loopback dial")
		}
		return nil
	}
	if dial.Host.IP.Zone() != "" {
		return invalidField(field+".Host", "IPv6 zones are not permitted")
	}
	addr := canonicalAddress(dial.Host.IP)
	if addr.IsUnspecified() {
		return invalidField(field+".Host", "unspecified addresses are not permitted")
	}
	if addr.IsMulticast() {
		return invalidField(field+".Host", "multicast addresses are not permitted")
	}
	if addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return invalidField(field+".Host", "the IPv4 broadcast address is not permitted")
	}
	if addr.IsLinkLocalUnicast() {
		return invalidField(field+".Host", "link-local dial locators are not permitted")
	}
	if addr.IsLoopback() && !bindAddr.IsLoopback() {
		return invalidField(field+".Host", "loopback dial requires a loopback bind")
	}
	if bindAddr.IsLoopback() && !addr.IsLoopback() {
		return invalidField(field+".Host", "loopback bind cannot publish a non-loopback dial")
	}
	return nil
}
