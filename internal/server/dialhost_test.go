package server

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestCanonicalDNSNameLowercasesAndStripsDot(t *testing.T) {
	t.Parallel()

	upper, err := CanonicalDNSName("TUNNEL.EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := CanonicalDNSName("tunnel.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if upper != "tunnel.example.com" || lower != upper {
		t.Fatalf("canonical = %q and %q", upper, lower)
	}
}

func TestCanonicalDNSNameRejectsUnsafeNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"",
		".",
		"tunnel..example.com",
		"-tunnel.example.com",
		"tunnel-.example.com",
		"tunnel.example.com/path",
		"tunnel.example.com:443",
		"*.example.com",
		"tünnel.example.com",
		"192.0.2.10",
		"::1",
		"fe80::1%eth0",
		strings.Repeat("a", 64) + ".example.com",
	} {
		if _, err := CanonicalDNSName(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestDialHostJSONRoundTripAndEquality(t *testing.T) {
	t.Parallel()

	ip := IPDialHost(netip.MustParseAddr("::ffff:192.0.2.10"))
	encoded, err := json.Marshal(ip)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"192.0.2.10"` {
		t.Fatalf("JSON = %s", encoded)
	}
	var decoded DialHost
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(IPDialHost(netip.MustParseAddr("192.0.2.10"))) {
		t.Fatalf("decoded = %+v", decoded)
	}

	var name DialHost
	if err := json.Unmarshal([]byte(`"TUNNEL.EXAMPLE.COM"`), &name); err != nil {
		t.Fatal(err)
	}
	if name.Name != "tunnel.example.com" || name.IP.IsValid() {
		t.Fatalf("name host = %+v", name)
	}
}
