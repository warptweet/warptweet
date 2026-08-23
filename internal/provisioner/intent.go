package provisioner

import (
	"os"
	"strings"

	"warptweet.com/warptweet/internal/routestate"
)

func persistRouteIntent(root, tunnelID, desired, bootID string, createIfMissing bool) error {
	store := routestate.Store{Root: root}
	exists, err := store.Exists(tunnelID)
	if err != nil {
		return err
	}
	if !exists {
		if !createIfMissing {
			return nil
		}
		if err := store.Reserve(tunnelID); err != nil {
			return err
		}
	}
	intent, err := store.LoadIntent(tunnelID)
	if err != nil {
		intent = routestate.Intent{
			Kind:          routestate.KindDesiredState,
			SchemaVersion: routestate.CurrentSchemaVersion,
			RouteID:       tunnelID,
			RestartPolicy: routestate.RestartUnlessStopped,
		}
	}
	intent.DesiredState = desired
	if desired == routestate.DesiredRunning && intent.RestartPolicy == routestate.RestartManual {
		intent.BootID = bootID
	}
	if desired == routestate.DesiredStopped {
		intent.BootID = ""
	}
	return store.WriteIntent(intent)
}

func linuxBootID() string {
	contents, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}
