package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestPolicyAllowsOnlyDirectTCPIPAndPinnedDestinations(t *testing.T) {
	t.Parallel()

	policy := mustPolicy(t)
	if err := policy.allowChannelType("direct-tcpip"); err != nil {
		t.Fatal(err)
	}
	for _, channelType := range []string{"session", "tun@openssh.com", "direct-streamlocal@openssh.com", "forwarded-tcpip"} {
		if err := policy.allowChannelType(channelType); err == nil {
			t.Fatalf("allowed channel type %q", channelType)
		}
	}
	if err := policy.allowGlobalRequest("keepalive@openssh.com"); err != nil {
		t.Fatal(err)
	}
	if err := policy.allowGlobalRequest("no-more-sessions@openssh.com"); err != nil {
		t.Fatal(err)
	}
	if err := policy.allowGlobalRequest("tcpip-forward"); err == nil {
		t.Fatal("allowed tcpip-forward")
	}
	if err := policy.allowDirectTCPIP(policy.Target); err != nil {
		t.Fatal(err)
	}
	if err := policy.allowDirectTCPIP(policy.Management); err != nil {
		t.Fatal(err)
	}
	other := netip.MustParseAddrPort("198.51.100.99:9")
	if err := policy.allowDirectTCPIP(other); err == nil {
		t.Fatal("allowed unpinned destination")
	}
}

func TestPolicyAdvertisesExactProfileAlgorithms(t *testing.T) {
	t.Parallel()

	policy := mustPolicy(t)
	if policy.Profile.KeyExchangeAlgorithm != "mlkem768x25519-sha256" {
		t.Fatalf("kex=%q", policy.Profile.KeyExchangeAlgorithm)
	}
	if policy.Profile.AuthenticationKeyType != "ssh-mldsa44-ed25519@openssh.com" {
		t.Fatalf("hostkey=%q", policy.Profile.AuthenticationKeyType)
	}
	if !strings.HasPrefix(policy.identification(), "SSH-2.0-WarpTweet_") {
		t.Fatalf("ident=%q", policy.identification())
	}
}

func mustPolicy(t testing.TB) Policy {
	t.Helper()
	config := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            strings.Repeat("a", 64),
		OpenSSHBundleManifestSHA256: strings.Repeat("b", 64),
		Network:                     server.PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722),
		Target: server.Endpoint{
			Address: netip.MustParseAddr("198.51.100.7"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        "/var/lib/warptweet/ssh/ssh_host_mldsa44_ed25519_key",
		AuthorizedKeysPath: "/var/lib/warptweet/authorized_keys/warptweet",
	}
	policy, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
