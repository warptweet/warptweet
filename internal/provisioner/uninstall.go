package provisioner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"warptweet.com/warptweet/internal/config"
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

func forgetRoute(root, routeID string) error {
	if err := config.ValidateTunnelID(routeID); err != nil {
		return err
	}
	if err := routestate.ValidateRouteID(routeID); err != nil {
		return err
	}
	store := routestate.Store{Root: root}
	if err := store.Remove(routeID); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func listRoutesJSON(root string) (string, error) {
	store := routestate.Store{Root: root}
	listed, err := store.List()
	if err != nil {
		return "", err
	}
	type routeJSON struct {
		RouteID       string `json:"route_id"`
		DesiredState  string `json:"desired_state,omitempty"`
		RestartPolicy string `json:"restart_policy,omitempty"`
		Listen        string `json:"listen_endpoint,omitempty"`
		Target        string `json:"target_endpoint,omitempty"`
		Authorization string `json:"authorization_not_after,omitempty"`
		Invalid       bool   `json:"invalid"`
		Error         string `json:"error,omitempty"`
	}
	payload := make([]routeJSON, 0, len(listed))
	for _, route := range listed {
		payload = append(payload, routeJSON{
			RouteID:       route.RouteID,
			DesiredState:  route.Intent.DesiredState,
			RestartPolicy: route.Intent.RestartPolicy,
			Listen:        route.Listen,
			Target:        route.Receipt.Target,
			Authorization: route.Receipt.AuthorizationNotAfter,
			Invalid:       route.Invalid,
			Error:         route.Error,
		})
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "routes": payload})
	if err != nil {
		return "", err
	}
	return string(append(raw, '\n')), nil
}
