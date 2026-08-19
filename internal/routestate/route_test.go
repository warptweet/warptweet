package routestate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRouteID(t *testing.T) {
	t.Parallel()

	if err := ValidateRouteID("staging-db"); err != nil {
		t.Fatalf("ValidateRouteID: %v", err)
	}
	for _, bad := range []string{"", "../etc", "foo/bar", ".hidden", "-dash", "has space", strings.Repeat("a", 65)} {
		if err := ValidateRouteID(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestShouldStartAtBoot(t *testing.T) {
	t.Parallel()

	if !ShouldStartAtBoot(Intent{DesiredState: DesiredRunning, RestartPolicy: RestartUnlessStopped}, "boot-1") {
		t.Fatal("unless-stopped running should start")
	}
	if ShouldStartAtBoot(Intent{DesiredState: DesiredStopped, RestartPolicy: RestartUnlessStopped}, "boot-1") {
		t.Fatal("stopped should not start")
	}
	if ShouldStartAtBoot(Intent{DesiredState: DesiredRunning, RestartPolicy: RestartManual, BootID: "boot-1"}, "boot-2") {
		t.Fatal("manual should not start on a new boot")
	}
	if !ShouldStartAtBoot(Intent{DesiredState: DesiredRunning, RestartPolicy: RestartManual, BootID: "boot-1"}, "boot-1") {
		t.Fatal("manual should start on the bound boot")
	}
}

func TestStoreReserveAndListInvalid(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.Reserve("staging-db"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := store.Reserve("staging-db"); err == nil {
		t.Fatal("Reserve overwrote an existing route")
	}
	if err := store.WriteIntent(Intent{
		Kind:          KindDesiredState,
		SchemaVersion: CurrentSchemaVersion,
		RouteID:       "staging-db",
		DesiredState:  DesiredRunning,
		RestartPolicy: RestartUnlessStopped,
	}); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	if err := store.WriteReceipt(Receipt{
		RouteID:                      "staging-db",
		ClientID:                     "aaaaaaaaaaaaaaaa",
		AuthorizationNotAfter:        "2026-09-15T12:00:00Z",
		AuthorizationDurationSeconds: 2592000,
		Generation:                   "20260816T120000Z",
	}); err != nil {
		t.Fatalf("WriteReceipt: %v", err)
	}
	if err := os.Mkdir(filepath.Join(store.Root, "broken"), 0o700); err != nil {
		t.Fatalf("mkdir broken: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.Root, "not-a-dir"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	listed, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("listed=%d, want 3", len(listed))
	}
	var sawValid, sawInvalid, sawFile bool
	for _, route := range listed {
		if route.RouteID == "staging-db" && !route.Invalid {
			sawValid = true
		}
		if route.RouteID == "broken" && route.Invalid {
			sawInvalid = true
		}
		if route.RouteID == "not-a-dir" && route.Invalid {
			sawFile = true
		}
	}
	if !sawValid || !sawInvalid || !sawFile {
		t.Fatalf("list did not keep valid and invalid routes visible: %+v", listed)
	}
}

func TestLoadIntentRejectsStrictJSONFailures(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.Reserve("db"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := filepath.Join(store.Root, "db", "desired.json")
	cases := []struct {
		name    string
		content []byte
	}{
		{name: "unknown field", content: []byte(`{"kind":"warptweet.route-desired-state","schema_version":1,"route_id":"db","desired_state":"running","restart_policy":"unless-stopped","updated_at":"2026-08-16T12:00:00Z","extra":true}` + "\n")},
		{name: "duplicate name", content: []byte(`{"kind":"warptweet.route-desired-state","schema_version":1,"route_id":"db","route_id":"db","desired_state":"running","restart_policy":"unless-stopped","updated_at":"2026-08-16T12:00:00Z"}` + "\n")},
		{name: "oversized", content: bytes.Repeat([]byte{'a'}, maxRouteDocumentBytes+1)},
		{name: "trailing value", content: []byte(`{"kind":"warptweet.route-desired-state","schema_version":1,"route_id":"db","desired_state":"running","restart_policy":"unless-stopped","updated_at":"2026-08-16T12:00:00Z"}{"x":1}` + "\n")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := os.WriteFile(path, testCase.content, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := store.LoadIntent("db")
			if err == nil || !errors.Is(err, ErrInvalidRoute) {
				t.Fatalf("LoadIntent err=%v", err)
			}
		})
	}
}

func TestReservePortRejectsCollision(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.ReservePort("staging-db", 15432); err != nil {
		t.Fatalf("ReservePort: %v", err)
	}
	if err := store.ReservePort("other-db", 15432); err == nil {
		t.Fatal("ReservePort accepted a listen-port collision")
	}
	if exists, err := store.Exists("other-db"); err != nil || exists {
		t.Fatalf("colliding route left behind exists=%v err=%v", exists, err)
	}
	if exists, err := store.Exists("staging-db"); err != nil || !exists {
		t.Fatalf("collision removed the owning route exists=%v err=%v", exists, err)
	}
	if err := store.ReservePort("staging-db", 15432); err != nil {
		t.Fatalf("same-route reservation retry: %v", err)
	}
}

func TestReservePortIdempotentForSameRouteAndPort(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.ReservePort("staging-db", 15432); err != nil {
		t.Fatalf("ReservePort: %v", err)
	}
	if err := store.ReservePort("staging-db", 15432); err != nil {
		t.Fatalf("ReservePort retry: %v", err)
	}
}

func TestWriteReceiptRequiresHostExpiry(t *testing.T) {
	t.Parallel()

	store := Store{Root: t.TempDir()}
	if err := store.Reserve("db"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := store.WriteReceipt(Receipt{RouteID: "db", ClientID: "c1"}); err == nil {
		t.Fatal("WriteReceipt accepted a receipt without host expiry")
	}
	if err := store.WriteReceipt(Receipt{
		RouteID:                      "db",
		ClientID:                     "c1",
		AcceptedAt:                   time.Now().UTC().Format(time.RFC3339Nano),
		AuthorizationNotAfter:        time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339Nano),
		AuthorizationDurationSeconds: 2592000,
		Generation:                   "20260816T120000Z",
	}); err != nil {
		t.Fatalf("WriteReceipt: %v", err)
	}
}

func TestWriteIntentRepairsExistingMode(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := Store{Root: root}
	routeDir := filepath.Join(root, "staging-db")
	if err := os.MkdirAll(routeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteIntent(Intent{
		Kind:          KindDesiredState,
		SchemaVersion: CurrentSchemaVersion,
		RouteID:       "staging-db",
		DesiredState:  DesiredRunning,
		RestartPolicy: RestartUnlessStopped,
	}); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	info, err := os.Stat(routeDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("route dir mode=%o, want 0750", info.Mode().Perm())
	}
}
