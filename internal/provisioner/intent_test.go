package provisioner

import (
	"context"
	"testing"

	"warptweet.com/warptweet/internal/routestate"
)

func TestPersistRouteIntentWritesBeforeProjection(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := persistRouteIntent(root, "db-primary", routestate.DesiredRunning, "boot-1", true); err != nil {
		t.Fatal(err)
	}
	store := routestate.Store{Root: root}
	intent, err := store.LoadIntent("db-primary")
	if err != nil {
		t.Fatal(err)
	}
	if intent.DesiredState != routestate.DesiredRunning {
		t.Fatalf("desired=%s", intent.DesiredState)
	}
	if err := persistRouteIntent(root, "db-primary", routestate.DesiredStopped, "", false); err != nil {
		t.Fatal(err)
	}
	intent, err = store.LoadIntent("db-primary")
	if err != nil {
		t.Fatal(err)
	}
	if intent.DesiredState != routestate.DesiredStopped || intent.BootID != "" {
		t.Fatalf("stopped intent=%+v", intent)
	}
}

func TestUninstallAllRoutesStopsAndRecordsDesiredStopped(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := persistRouteIntent(root, "db-primary", routestate.DesiredRunning, "", true); err != nil {
		t.Fatal(err)
	}
	var stopped []string
	if _, err := uninstallAllRoutes(context.Background(), root, func(_ context.Context, routeID string) error {
		stopped = append(stopped, routeID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(stopped) != 1 || stopped[0] != "db-primary" {
		t.Fatalf("stopped=%v", stopped)
	}
	intent, err := (routestate.Store{Root: root}).LoadIntent("db-primary")
	if err != nil {
		t.Fatal(err)
	}
	if intent.DesiredState != routestate.DesiredStopped {
		t.Fatalf("desired=%s", intent.DesiredState)
	}
}
