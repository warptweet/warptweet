//go:build !linux

package inspectnet

import (
	"fmt"
	"net/netip"
)

func KernelRouteLookup(family int, dst netip.Addr) (RouteReply, error) {
	_ = family
	_ = dst
	return RouteReply{}, fmt.Errorf("WarpTweet inspect-network requires Linux")
}
