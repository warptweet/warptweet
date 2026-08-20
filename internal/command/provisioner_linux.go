//go:build linux

package command

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/provisioner"
)

func useInstalledProvisioner() bool {
	if os.Geteuid() == 0 {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return false
	}
	return filepath.Clean(resolved) == installlayout.ControllerPath
}

func callInstalledProvisioner(
	ctx context.Context,
	request provisioner.Request,
	stdout io.Writer,
) (bool, error) {
	if !useInstalledProvisioner() {
		return false, nil
	}
	response, err := provisioner.Call(ctx, request)
	if err != nil {
		return true, err
	}
	if response.Output != "" {
		if _, err := io.WriteString(stdout, response.Output); err != nil {
			return true, fmt.Errorf("write provisioner response: %w", err)
		}
	}
	return true, nil
}
