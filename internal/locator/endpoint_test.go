package locator

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestPublishedEndpointSetEqualIncludesGeneration(t *testing.T) {
	t.Parallel()

	left := PublishedEndpointSet{
		Generation: 1,
		Data:       DialEndpoint{Host: IPDialHost(netip.MustParseAddr("192.0.2.10")), Port: 2222},
		Enrollment: DialEndpoint{Host: MustParseDialHost(t, "enroll.example.com"), Port: 29722},
	}
	right, err := left.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !left.Equal(right) {
		t.Fatal("canonical copy was not equal")
	}
	right.Generation = 2
	if left.Equal(right) {
		t.Fatal("generation was ignored")
	}
	if !SamePublishedLocators(left, right) {
		t.Fatal("SamePublishedLocators should ignore generation")
	}
	cased := left
	cased.Enrollment.Host = MustParseDialHost(t, "ENROLL.EXAMPLE.COM")
	if !left.Equal(cased) {
		t.Fatal("DNS casing was not canonicalized")
	}
}

func TestPublishedEndpointSetJSONUsesContractFieldNames(t *testing.T) {
	t.Parallel()

	set := PublishedEndpointSet{
		Generation: 1,
		Data:       DialEndpoint{Host: IPDialHost(netip.MustParseAddr("192.0.2.10")), Port: 2222},
		Enrollment: DialEndpoint{Host: MustParseDialHost(t, "enroll.example.com"), Port: 8443},
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	for _, required := range []string{
		`"published_endpoint_generation":1`,
		`"data":{"host":"192.0.2.10","port":2222}`,
		`"enrollment":{"host":"enroll.example.com","port":8443}`,
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("JSON omitted %s: %s", required, encoded)
		}
	}
}

func MustParseDialHost(t *testing.T, value string) DialHost {
	t.Helper()
	host, err := ParseDialHost(value)
	if err != nil {
		t.Fatal(err)
	}
	return host
}
