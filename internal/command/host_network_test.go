package command

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/inspectnet"
	"warptweet.com/warptweet/internal/server"
)

func TestResolveDataDialRestoresStoredWhenAdvertiseOmitted(t *testing.T) {
	t.Parallel()

	stored := &server.Config{Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722)}
	stored.Network.Data.Dial = server.DialEndpoint{
		Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")),
		Port: 2222,
	}
	pub, err := resolveHostPublication(hostPublicationFlags{
		Listen: onceStringFlag{name: "--listen", value: "10.168.0.2:2222", set: true},
	}, stored, func() (netip.Addr, error) {
		t.Fatal("discover called")
		return netip.Addr{}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := pub.DataDial.Host.Canonical()
	if host != "34.20.174.226" || pub.DataDial.Port != 2222 {
		t.Fatalf("dial=%+v", pub.DataDial)
	}
	enrollHost, _ := pub.EnrollDial.Host.Canonical()
	if enrollHost != "34.20.174.226" || pub.EnrollDial.Port != enrollment.DefaultEnrollmentPort {
		t.Fatalf("enroll dial=%+v", pub.EnrollDial)
	}
}

func TestResolveDataDialEmptyAdvertiseResetsToListen(t *testing.T) {
	t.Parallel()

	stored := &server.Config{Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722)}
	stored.Network.Data.Dial = server.DialEndpoint{
		Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")),
		Port: 2222,
	}
	pub, err := resolveHostPublication(hostPublicationFlags{
		Advertise: onceStringFlag{name: "--advertise", value: "", set: true},
	}, stored, func() (netip.Addr, error) {
		t.Fatal("discover called")
		return netip.Addr{}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := pub.DataDial.Host.Canonical()
	if host != "10.168.0.2" {
		t.Fatalf("empty advertise did not reset: %s", host)
	}
}

func TestResolveDataDialEqualToListenIsExplicitReset(t *testing.T) {
	t.Parallel()

	stored := &server.Config{Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722)}
	stored.Network.Data.Dial = server.DialEndpoint{
		Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")),
		Port: 2222,
	}
	pub, err := resolveHostPublication(hostPublicationFlags{
		Advertise: onceStringFlag{name: "--advertise", value: "10.168.0.2:2222", set: true},
	}, stored, func() (netip.Addr, error) {
		t.Fatal("discover called")
		return netip.Addr{}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := pub.DataDial.Host.Canonical()
	if host != "10.168.0.2" {
		t.Fatalf("equal advertise did not reset: %s", host)
	}
}

func TestResolveAdvertiseDNSAndIndependentEnrollment(t *testing.T) {
	t.Parallel()

	pub, err := resolveHostPublication(hostPublicationFlags{
		Listen:          onceStringFlag{name: "--listen", value: "10.168.0.2:2222", set: true},
		Advertise:       onceStringFlag{name: "--advertise", value: "TUNNEL.EXAMPLE.COM:443", set: true},
		EnrollListen:    onceStringFlag{name: "--enroll-listen", value: "10.168.0.2:8443", set: true},
		EnrollAdvertise: onceStringFlag{name: "--enroll-advertise", value: "enroll.example.com:8443", set: true},
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := pub.DataDial.Host.Canonical()
	if host != "tunnel.example.com" || pub.DataDial.Port != 443 {
		t.Fatalf("data dial=%+v", pub.DataDial)
	}
	if pub.EnrollListen.Port != 8443 {
		t.Fatalf("enroll listen=%+v", pub.EnrollListen)
	}
	enrollHost, _ := pub.EnrollDial.Host.Canonical()
	if enrollHost != "enroll.example.com" || pub.EnrollDial.Port != 8443 {
		t.Fatalf("enroll dial=%+v", pub.EnrollDial)
	}
}

func TestResolveListenInterfacePersistsAddressNotName(t *testing.T) {
	t.Parallel()

	ifaces := []inspectnet.Interface{{
		Index: 2,
		Name:  "ens4",
		Flags: net.FlagUp,
		Addrs: []netip.Addr{netip.MustParseAddr("10.168.0.2")},
	}}
	pub, err := resolveHostPublication(hostPublicationFlags{
		ListenInterface: onceStringFlag{name: "--listen-interface", value: "ens4", set: true},
	}, nil, func() (netip.Addr, error) {
		t.Fatal("discover called")
		return netip.Addr{}, nil
	}, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	if pub.DataListen.Address.String() != "10.168.0.2" || pub.DataListen.Port != 2222 {
		t.Fatalf("listen=%+v", pub.DataListen)
	}
}

func TestResolveRejectsListenCombinedWithInterface(t *testing.T) {
	t.Parallel()

	_, err := resolveHostPublication(hostPublicationFlags{
		Listen:          onceStringFlag{name: "--listen", value: "10.168.0.2:2222", set: true},
		ListenInterface: onceStringFlag{name: "--listen-interface", value: "ens4", set: true},
	}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--listen-interface") {
		t.Fatalf("error=%v", err)
	}
}
