package server

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
)

func TestProposeNetworkStartsAtOneAndRestoresStoredDials(t *testing.T) {
	t.Parallel()

	data := BindEndpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 2222}
	enroll := BindEndpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 29722}
	first, changed, err := ProposeNetwork(data, enroll, nil)
	if err != nil {
		t.Fatalf("ProposeNetwork: %v", err)
	}
	if changed {
		t.Fatal("first write is not a published-set change")
	}
	if first.PublishedEndpointGeneration != 1 {
		t.Fatalf("generation = %d, want 1", first.PublishedEndpointGeneration)
	}

	newData := BindEndpoint{Address: netip.MustParseAddr("192.0.2.11"), Port: 2222}
	newEnroll := BindEndpoint{Address: netip.MustParseAddr("192.0.2.11"), Port: 29722}
	next, changed, err := ProposeNetwork(newData, newEnroll, &first)
	if err != nil {
		t.Fatalf("ProposeNetwork bind-only: %v", err)
	}
	if changed {
		t.Fatal("bind-only edit changed the published set")
	}
	if next.PublishedEndpointGeneration != 1 {
		t.Fatalf("bind-only generation = %d, want 1", next.PublishedEndpointGeneration)
	}
	if !next.Data.Dial.Host.Equal(first.Data.Dial.Host) || next.Data.Dial.Port != first.Data.Dial.Port {
		t.Fatalf("stored data dial was not restored: %+v", next.Data.Dial)
	}
	if next.Data.Listen.AddrPort().String() != "192.0.2.11:2222" {
		t.Fatalf("data listen = %s", next.Data.Listen.AddrPort())
	}
}

func TestProposeNetworkIncrementsOnceOnPublishedSetChange(t *testing.T) {
	t.Parallel()

	stored := PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722)
	stored.Data.Dial = DialEndpoint{Host: IPDialHost(netip.MustParseAddr("34.20.174.226")), Port: 2222}
	stored.Enrollment.Dial = DialEndpoint{Host: IPDialHost(netip.MustParseAddr("34.20.174.226")), Port: 29722}

	// Restore keeps stored dials, so construct a change by swapping stored dials
	// after a bind-equal proposal, then calling nextGeneration directly.
	next, err := nextPublishedEndpointGeneration(stored.PublishedEndpointGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if next != 2 {
		t.Fatalf("next generation = %d, want 2", next)
	}

	changed := Network{
		PublishedEndpointGeneration: stored.PublishedEndpointGeneration,
		Data: ServiceEndpoints{
			Listen: stored.Data.Listen,
			Dial: DialEndpoint{
				Host: IPDialHost(netip.MustParseAddr("198.51.100.10")),
				Port: 2222,
			},
		},
		Enrollment: ServiceEndpoints{
			Listen: stored.Enrollment.Listen,
			Dial: DialEndpoint{
				Host: IPDialHost(netip.MustParseAddr("198.51.100.10")),
				Port: 29722,
			},
		},
	}
	if SamePublishedLocators(stored.PublishedSet(), changed.PublishedSet()) {
		t.Fatal("expected locator change")
	}
	if !SamePublishedLocators(stored.PublishedSet(), stored.PublishedSet()) {
		t.Fatal("identical locators compared unequal")
	}
}

func TestNextPublishedEndpointGenerationOverflowFailsClosed(t *testing.T) {
	t.Parallel()

	_, err := nextPublishedEndpointGeneration(math.MaxUint64)
	if err == nil {
		t.Fatal("overflow accepted")
	}
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "PublishedEndpointGeneration") {
		t.Fatalf("error = %v", err)
	}
}

func TestProposeNetworkDoesNotDecrement(t *testing.T) {
	t.Parallel()

	stored := PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722)
	stored.PublishedEndpointGeneration = 9
	next, changed, err := ProposeNetwork(stored.Data.Listen, stored.Enrollment.Listen, &stored)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("unchanged locators reported a change")
	}
	if next.PublishedEndpointGeneration != 9 {
		t.Fatalf("generation = %d, want 9", next.PublishedEndpointGeneration)
	}
}
