//go:build !darwin && !linux

package command

import (
	"context"
	"io"

	"warptweet.com/warptweet/internal/provisioner"
)

func useInstalledProvisioner() bool {
	return false
}

func callInstalledProvisioner(context.Context, provisioner.Request, io.Writer) (bool, error) {
	return false, nil
}
