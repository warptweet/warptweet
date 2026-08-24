package locator

import "fmt"

// DialEndpoint is a published locator: a canonical host and TCP port.
type DialEndpoint struct {
	Host DialHost `json:"host"`
	Port uint16   `json:"port"`
}

// Equal reports canonical host:port equality.
func (endpoint DialEndpoint) Equal(other DialEndpoint) bool {
	return endpoint.Port == other.Port && endpoint.Host.Equal(other.Host)
}

// PublishedEndpointSet is the atomic published locator carried by invite,
// proof, ClientRecord, receipts, and routes. EnrollmentRequest does not
// carry it. JSON uses published_endpoint_generation, data, and enrollment.
type PublishedEndpointSet struct {
	Generation uint64       `json:"published_endpoint_generation"`
	Data       DialEndpoint `json:"data"`
	Enrollment DialEndpoint `json:"enrollment"`
}

// SamePublishedLocators reports whether the canonical data and enrollment
// dials are equal. It ignores published_endpoint_generation.
func SamePublishedLocators(left, right PublishedEndpointSet) bool {
	return left.Data.Equal(right.Data) && left.Enrollment.Equal(right.Enrollment)
}

// Equal reports complete canonical equality, including generation.
func (set PublishedEndpointSet) Equal(other PublishedEndpointSet) bool {
	left, leftErr := set.Canonical()
	right, rightErr := other.Canonical()
	return leftErr == nil && rightErr == nil &&
		left.Generation == right.Generation &&
		SamePublishedLocators(left, right)
}

// Canonical lowercases DNS names, unmaps IPs, and rejects an incomplete set.
func (set PublishedEndpointSet) Canonical() (PublishedEndpointSet, error) {
	if set.Generation == 0 {
		return PublishedEndpointSet{}, fmt.Errorf("published_endpoint_generation must be at least 1")
	}
	if set.Data.Port == 0 || set.Enrollment.Port == 0 {
		return PublishedEndpointSet{}, fmt.Errorf("published ports must be nonzero")
	}
	dataHost, err := set.Data.Host.Canonical()
	if err != nil {
		return PublishedEndpointSet{}, fmt.Errorf("data host: %w", err)
	}
	enrollHost, err := set.Enrollment.Host.Canonical()
	if err != nil {
		return PublishedEndpointSet{}, fmt.Errorf("enrollment host: %w", err)
	}
	data, err := ParseDialHost(dataHost)
	if err != nil {
		return PublishedEndpointSet{}, fmt.Errorf("data host: %w", err)
	}
	enroll, err := ParseDialHost(enrollHost)
	if err != nil {
		return PublishedEndpointSet{}, fmt.Errorf("enrollment host: %w", err)
	}
	canonical := PublishedEndpointSet{
		Generation: set.Generation,
		Data:       DialEndpoint{Host: data, Port: set.Data.Port},
		Enrollment: DialEndpoint{Host: enroll, Port: set.Enrollment.Port},
	}
	if SamePublishedLocators(canonical, PublishedEndpointSet{
		Data:       canonical.Enrollment,
		Enrollment: canonical.Data,
	}) {
		return PublishedEndpointSet{}, fmt.Errorf("data and enrollment locators must not share the same canonical host:port")
	}
	return canonical, nil
}
