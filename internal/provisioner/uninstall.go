package provisioner

import (
	"context"
	"fmt"

	"warptweet.com/warptweet/internal/routestate"
)

func uninstallAllRoutes(ctx context.Context, root string, stop func(context.Context, string) error) (string, error) {
	store := routestate.Store{Root: root}
	listed, err := store.List()
	if err != nil {
		return "", err
	}
	stopped := make([]string, 0, len(listed))
	failed := map[string]string{}
	for _, route := range listed {
		if route.Invalid || route.RouteID == "" {
			continue
		}
		if err := persistRouteIntent(root, route.RouteID, routestate.DesiredStopped, "", false); err != nil {
			failed[route.RouteID] = err.Error()
			continue
		}
		if err := stop(ctx, route.RouteID); err != nil {
			failed[route.RouteID] = err.Error()
			continue
		}
		stopped = append(stopped, route.RouteID)
	}
	output, err := encodeOutput(map[string]any{
		"status":      "stopped_all",
		"stopped":     stopped,
		"stop_errors": failed,
	})
	if err != nil {
		return "", err
	}
	if len(failed) > 0 {
		return output, fmt.Errorf("uninstall: %d routes failed to stop", len(failed))
	}
	return output, nil
}
