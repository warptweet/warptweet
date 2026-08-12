//go:build linux

package engine

import (
	"fmt"

	"warptweet.com/warptweet/internal/artifactprofile"
	linuxplatform "warptweet.com/warptweet/internal/platform/linux"
)

func requireProductionClientPlatform() error {
	platform, err := linuxplatform.New()
	if err != nil {
		return err
	}
	if err := platform.RequireSupported(); err != nil {
		return err
	}
	selected, err := platform.ArtifactProfile()
	if err != nil {
		return err
	}
	if selected.ID != artifactprofile.LinuxAMD64 && selected.ID != artifactprofile.LinuxARM64 {
		return fmt.Errorf("production OpenSSH client preflight requires a supported Linux artifact profile, got %q", selected.ID)
	}
	return nil
}
