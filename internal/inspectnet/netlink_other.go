//go:build !linux

package inspectnet

import (
	"fmt"
	"net/netip"
)

// KernelRouteLookup is not a Darwin host. Public `host` fails closed before
// calling this. Tests inject fake lookups instead.
func KernelRouteLookup(family int, dst netip.Addr) (RouteReply, error) {
	_ = family
	_ = dst
	return RouteReply{}, fmt.Errorf("WarpTweet inspect-network requires Linux")
}
