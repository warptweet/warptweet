package command

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/locator"
)

func TestResolveManifestServerSingleCandidateSkipsConnect(t *testing.T) {
	t.Parallel()

	dialed := false
	plan, selected, err := resolveManifestServer(context.Background(), config.Config{
		Server: config.Server{Host: "192.0.2.10", Port: 2222},
	}, locator.ResolveOptions{
		Dial: func(context.Context, netip.Addr, uint16, time.Duration) error {
			dialed = true
			return errors.New("must not dial a single candidate")
		},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if dialed {
		t.Fatal("single candidate walked TCP")
	}
	if selected.String() != "192.0.2.10" || len(plan.Candidates) != 1 {
		t.Fatalf("selected=%s plan=%v", selected, plan.Candidates)
	}
}

func TestResolveManifestServerWalksMultipleCandidatesWhenConnecting(t *testing.T) {
	t.Parallel()

	var attempts []string
	_, selected, err := resolveManifestServer(context.Background(), config.Config{
		Server: config.Server{Host: "tunnel.example.com", Port: 2222},
	}, locator.ResolveOptions{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.10"),
			}, nil
		},
		Dial: func(_ context.Context, addr netip.Addr, port uint16, _ time.Duration) error {
			attempts = append(attempts, addr.String())
			if addr.String() != "192.0.2.10" || port != 2222 {
				return errors.New("refused")
			}
			return nil
		},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if selected.String() != "192.0.2.10" {
		t.Fatalf("selected=%s", selected)
	}
	if len(attempts) != 2 || attempts[0] != "2001:db8::1" || attempts[1] != "192.0.2.10" {
		t.Fatalf("attempts=%v", attempts)
	}
}

func TestResolveManifestServerConnectFalseTakesFirstCandidate(t *testing.T) {
	t.Parallel()

	dialed := false
	_, selected, err := resolveManifestServer(context.Background(), config.Config{
		Server: config.Server{Host: "tunnel.example.com", Port: 2222},
	}, locator.ResolveOptions{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.10"),
			}, nil
		},
		Dial: func(context.Context, netip.Addr, uint16, time.Duration) error {
			dialed = true
			return nil
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if dialed {
		t.Fatal("connect=false dialed")
	}
	if selected.String() != "2001:db8::1" {
		t.Fatalf("selected=%s", selected)
	}
}

func TestResolveManifestServerAllowsLoopbackIP(t *testing.T) {
	t.Parallel()

	_, selected, err := resolveManifestServer(context.Background(), config.Config{
		Server: config.Server{Host: "127.0.0.1", Port: 2222},
	}, locator.ResolveOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if selected.String() != "127.0.0.1" {
		t.Fatalf("selected=%s", selected)
	}
}
