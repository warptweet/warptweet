//go:build !darwin && !linux

package command

import (
	"context"
	"io"

	"warptweet.com/warptweet/internal/provisioner"
)

func callInstalledProvisioner(context.Context, provisioner.Request, io.Writer) (bool, error) {
	return false, nil
}
