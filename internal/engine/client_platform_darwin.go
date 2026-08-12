//go:build darwin

package engine

import (
	"fmt"

	"warptweet.com/warptweet/internal/artifactprofile"
	darwinplatform "warptweet.com/warptweet/internal/platform/darwin"
)

func requireProductionClientPlatform() error {
	platform, err := darwinplatform.New()
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
	if selected.ID != artifactprofile.DarwinAMD64 && selected.ID != artifactprofile.DarwinARM64 {
		return fmt.Errorf("production OpenSSH client preflight requires a supported Darwin artifact profile, got %q", selected.ID)
	}
	return nil
}
