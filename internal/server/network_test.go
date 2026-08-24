package server

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
)

func TestProposeNetworkStartsAtOneAndKeepsStoredDialsOnBindOnly(t *testing.T) {
	t.Parallel()

	data := BindEndpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 2222}
	enroll := BindEndpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 29722}
	first, changed, err := ProposeNetwork(data, enroll, DialFromBind(data), DialFromBind(enroll), nil)
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
	next, changed, err := ProposeNetwork(newData, newEnroll, first.Data.Dial, first.Enrollment.Dial, &first)
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
		t.Fatalf("stored data dial was not kept: %+v", next.Data.Dial)
	}
	if next.Data.Listen.AddrPort().String() != "192.0.2.11:2222" {
		t.Fatalf("data listen = %s", next.Data.Listen.AddrPort())
	}
}

func TestProposeNetworkIncrementsOnceOnPublishedSetChange(t *testing.T) {
	t.Parallel()

	stored := PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722)
	dataDial := DialEndpoint{Host: IPDialHost(netip.MustParseAddr("198.51.100.10")), Port: 2222}
	enrollDial := DialEndpoint{Host: IPDialHost(netip.MustParseAddr("198.51.100.10")), Port: 29722}
	next, changed, err := ProposeNetwork(stored.Data.Listen, stored.Enrollment.Listen, dataDial, enrollDial, &stored)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("locator change reported unchanged")
	}
	if next.PublishedEndpointGeneration != 2 {
		t.Fatalf("generation = %d, want 2", next.PublishedEndpointGeneration)
	}
	if !next.Data.Dial.Host.Equal(dataDial.Host) || next.Data.Dial.Port != dataDial.Port {
		t.Fatalf("data dial = %+v", next.Data.Dial)
	}
}

func TestProposeNetworkOverflowFailsClosed(t *testing.T) {
	t.Parallel()

	stored := PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722)
	stored.PublishedEndpointGeneration = math.MaxUint64
	dataDial := DialEndpoint{Host: IPDialHost(netip.MustParseAddr("198.51.100.10")), Port: 2222}
	enrollDial := DialEndpoint{Host: IPDialHost(netip.MustParseAddr("198.51.100.10")), Port: 29722}
	_, changed, err := ProposeNetwork(stored.Data.Listen, stored.Enrollment.Listen, dataDial, enrollDial, &stored)
	if err == nil || !changed {
		t.Fatal("overflow accepted")
	}
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "PublishedEndpointGeneration") {
		t.Fatalf("error = %v", err)
	}
}

func TestProposeNetworkRejectsStoredGenerationZero(t *testing.T) {
	t.Parallel()

	stored := PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722)
	stored.PublishedEndpointGeneration = 0
	_, _, err := ProposeNetwork(stored.Data.Listen, stored.Enrollment.Listen, stored.Data.Dial, stored.Enrollment.Dial, &stored)
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v", err)
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
	if _, err := nextPublishedEndpointGeneration(0); err == nil {
		t.Fatal("generation 0 incremented")
	}
}

func TestProposeNetworkDoesNotDecrement(t *testing.T) {
	t.Parallel()

	stored := PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722)
	stored.PublishedEndpointGeneration = 9
	next, changed, err := ProposeNetwork(stored.Data.Listen, stored.Enrollment.Listen, stored.Data.Dial, stored.Enrollment.Dial, &stored)
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
