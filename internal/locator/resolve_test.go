package locator

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestFilterAnswersUnmapsDedupsCapsAndRejectsUnsafe(t *testing.T) {
	t.Parallel()

	answers := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::ffff:192.0.2.10"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("ff02::1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::3"),
		netip.MustParseAddr("2001:db8::4"),
		netip.MustParseAddr("2001:db8::5"),
		netip.MustParseAddr("192.0.2.11"),
		netip.MustParseAddr("192.0.2.12"),
		netip.MustParseAddr("192.0.2.13"),
		netip.MustParseAddr("192.0.2.14"),
		netip.MustParseAddr("192.0.2.15"),
	}
	got := FilterAnswers(answers, false)
	want := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.11"),
		netip.MustParseAddr("2001:db8::3"),
		netip.MustParseAddr("192.0.2.12"),
		netip.MustParseAddr("2001:db8::4"),
		netip.MustParseAddr("192.0.2.13"),
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestFilterAnswersAllowsLoopbackWhenRequested(t *testing.T) {
	t.Parallel()

	got := FilterAnswers([]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, true)
	if len(got) != 2 || got[0].String() != "::1" || got[1].String() != "127.0.0.1" {
		t.Fatalf("got %v", got)
	}
	if filtered := FilterAnswers([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, false); len(filtered) != 0 {
		t.Fatalf("loopback leaked: %v", filtered)
	}
}

func TestInterleaveFamiliesDoesNotStarveIPv4(t *testing.T) {
	t.Parallel()

	v6 := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::3"),
		netip.MustParseAddr("2001:db8::4"),
	}
	v4 := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	got := InterleaveFamilies(v6, v4)
	if got[0].Is4() || got[1].String() != "192.0.2.10" {
		t.Fatalf("IPv4 was not attempted second: %v", got)
	}
}

func TestResolveIPSkipsLookup(t *testing.T) {
	t.Parallel()

	lookupCalled := false
	plan, err := Resolve(context.Background(), IPDialHost(netip.MustParseAddr("192.0.2.10")), ResolveOptions{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			lookupCalled = true
			return nil, errors.New("lookup must not run for IP locators")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookupCalled {
		t.Fatal("IP locator queried DNS")
	}
	if len(plan.Candidates) != 1 || plan.Candidates[0].String() != "192.0.2.10" {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestResolveDNSQueriesAbsoluteName(t *testing.T) {
	t.Parallel()

	var queried string
	plan, err := Resolve(context.Background(), DialHost{Name: "TUNNEL.EXAMPLE.COM"}, ResolveOptions{
		Lookup: func(_ context.Context, name string) ([]netip.Addr, error) {
			queried = name
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.10"),
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if queried != "tunnel.example.com." {
		t.Fatalf("queried %q", queried)
	}
	if plan.Host.Name != "tunnel.example.com" {
		t.Fatalf("host=%+v", plan.Host)
	}
	if len(plan.Candidates) != 2 || plan.Candidates[0].Is4() || plan.Candidates[1].Is6() {
		t.Fatalf("candidates=%v", plan.Candidates)
	}
}

func TestSelectWalksInterleavedCandidatesUntilSuccess(t *testing.T) {
	t.Parallel()

	plan := ResolvedDialPlan{
		Host: DialHost{Name: "tunnel.example.com"},
		Candidates: []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("2001:db8::2"),
		},
	}
	var attempts []string
	selected, err := Select(context.Background(), plan, 2222, ResolveOptions{
		Dial: func(_ context.Context, addr netip.Addr, port uint16, _ time.Duration) error {
			attempts = append(attempts, addr.String())
			if addr.String() != "192.0.2.10" || port != 2222 {
				return errors.New("refused")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected.String() != "192.0.2.10" {
		t.Fatalf("selected %s", selected)
	}
	if len(attempts) != 2 || attempts[0] != "2001:db8::1" || attempts[1] != "192.0.2.10" {
		t.Fatalf("attempts=%v", attempts)
	}
}

func TestSelectRecordsTCPConnectClass(t *testing.T) {
	t.Parallel()

	_, err := Select(context.Background(), ResolvedDialPlan{
		Candidates: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}, 2222, ResolveOptions{
		Dial: func(context.Context, netip.Addr, uint16, time.Duration) error {
			return errors.New("connection refused")
		},
	})
	if ErrorClass(err) != ClassTCPConnect {
		t.Fatalf("class=%q err=%v", ErrorClass(err), err)
	}
}

func TestSelectStopsOnCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var attempts int
	_, err := Select(ctx, ResolvedDialPlan{
		Candidates: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("192.0.2.11"),
		},
	}, 2222, ResolveOptions{
		Dial: func(context.Context, netip.Addr, uint16, time.Duration) error {
			attempts++
			return errors.New("refused")
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if ErrorClass(err) != ClassTCPConnect {
		t.Fatalf("class=%q err=%v", ErrorClass(err), err)
	}
	if attempts != 0 {
		t.Fatalf("attempts=%d", attempts)
	}
}

func TestResolveEmptyAnswersAreDNSResolution(t *testing.T) {
	t.Parallel()

	_, err := Resolve(context.Background(), DialHost{Name: "missing.example.com"}, ResolveOptions{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("224.0.0.1")}, nil
		},
	})
	if ErrorClass(err) != ClassDNSResolution {
		t.Fatalf("class=%q err=%v", ErrorClass(err), err)
	}
}
