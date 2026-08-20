//go:build linux

package command

import "warptweet.com/warptweet/internal/installlayout"

func requireServiceManagedRun() error {
	return requireDedicatedServiceRun(
		installlayout.ClientServiceUser,
		installlayout.ClientServiceGroup,
		installlayout.LinuxClientUID,
		installlayout.LinuxClientGID,
		installlayout.ControllerPath,
	)
}
