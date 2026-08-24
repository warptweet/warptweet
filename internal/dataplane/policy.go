package dataplane

import (
	"fmt"
	"net/netip"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grantsession"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const (
	identPrefix = "SSH-2.0-WarpTweet_"

	channelDirectTCPIP = "direct-tcpip"
	globalKeepalive    = "keepalive@openssh.com"
	globalNoMoreSess   = "no-more-sessions@openssh.com"
)

// Policy is the immutable data-plane contract for one host.
type Policy struct {
	Profile            profile.Profile
	Listen             netip.AddrPort
	Target             netip.AddrPort
	Management         netip.AddrPort
	HostKeyPath        string
	AuthorizedKeysPath string
	HostSignSocket     string
	Grant              *grantsession.Authority
	ControlSocket      string
	RekeyAfter         uint64
	MaxChannels        int
	MaxConnsPerSource  int
}

// HostSigner isolates host private-key use from the network parser.
type HostSigner interface {
	Public() ([]byte, error)
	Sign([]byte) ([]byte, error)
}

// NewPolicy derives the data-plane policy from a validated server manifest.
func NewPolicy(config server.Config) (Policy, error) {
	if err := server.Validate(config); err != nil {
		return Policy{}, err
	}
	selected, err := profile.Lookup(config.ProfileID)
	if err != nil {
		return Policy{}, err
	}
	return Policy{
		Profile: selected,
		Listen:  config.Network.Data.Listen.AddrPort(),
		Target: netip.AddrPortFrom(
			config.Target.Address.Unmap(),
			uint16(config.Target.Port),
		),
		Management: netip.AddrPortFrom(
			netip.MustParseAddr("127.0.0.1"),
			enrollment.DefaultManagementPort,
		),
		HostKeyPath:        config.HostKeyPath,
		AuthorizedKeysPath: config.AuthorizedKeysPath,
	}, nil
}

func (policy Policy) identification() string {
	return identPrefix + "tcp1"
}

func (policy Policy) allowChannelType(channelType string) error {
	if channelType == channelDirectTCPIP {
		return nil
	}
	return fmt.Errorf("WarpTweet allows only direct-tcpip channels, not %q", channelType)
}

func (policy Policy) allowGlobalRequest(requestType string) error {
	switch requestType {
	case globalKeepalive, globalNoMoreSess:
		return nil
	default:
		return fmt.Errorf("WarpTweet refused SSH global request %q", requestType)
	}
}

func (policy Policy) allowDirectTCPIP(destination netip.AddrPort) error {
	dest := netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if dest == policy.Target || dest == policy.Management {
		return nil
	}
	return fmt.Errorf("direct-tcpip destination %s is not permitted", dest)
}

func (policy Policy) maxConnsPerSource() int {
	if policy.MaxConnsPerSource < 0 {
		return policy.MaxConnsPerSource
	}
	if policy.MaxConnsPerSource == 0 {
		return defaultMaxConnsPerSource
	}
	return policy.MaxConnsPerSource
}
