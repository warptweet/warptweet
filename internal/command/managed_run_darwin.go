//go:build darwin

package command

import "warptweet.com/warptweet/internal/installlayout"

func requireServiceManagedRun() error {
	return requireDedicatedServiceRun(
		installlayout.DarwinClientServiceUser,
		installlayout.DarwinClientServiceGroup,
		0,
		0,
		installlayout.DarwinControllerPath,
	)
}
