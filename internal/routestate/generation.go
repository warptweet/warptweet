package routestate

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"warptweet.com/warptweet/internal/grantsession"
)

const (
	KindActive        = "warptweet.route-active-generation"
	KindReservation   = "warptweet.route-reservation"
	DefaultListenPort = 15432
)

// Active names the immutable generation currently selected for a route.
type Active struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
	RouteID       string `json:"route_id"`
	Generation    string `json:"generation"`
}

// Reservation is the atomic route-id and listen-port claim.
type Reservation struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
	RouteID       string `json:"route_id"`
	ListenPort    uint16 `json:"listen_port"`
}

// ValidateGenerationID rejects unsafe generation names.
func ValidateGenerationID(generation string) error {
	if generation == "" || len(generation) > 64 {
		return fmt.Errorf("%w: generation id must be 1-64 characters", ErrInvalidRoute)
	}
	if strings.Contains(generation, "..") || strings.ContainsAny(generation, "/\\:") {
		return fmt.Errorf("%w: generation id must not contain path characters", ErrInvalidRoute)
	}
	for i, r := range generation {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
			if i == 0 {
				return fmt.Errorf("%w: generation id must start with an alphanumeric character", ErrInvalidRoute)
			}
		default:
			return fmt.Errorf("%w: generation id contains forbidden character %q", ErrInvalidRoute, r)
		}
	}
	return nil
}

func (store Store) generationDir(routeID, generation string) (string, error) {
	if err := ValidateRouteID(routeID); err != nil {
		return "", err
	}
	if err := ValidateGenerationID(generation); err != nil {
		return "", err
	}
	return filepath.Join(store.Root, routeID, "generations", generation), nil
}

// GenerationDir returns the immutable generation directory.
func (store Store) GenerationDir(routeID, generation string) (string, error) {
	return store.generationDir(routeID, generation)
}

// ManifestPath returns the active generation client.wt path.
func (store Store) ManifestPath(routeID string) (string, error) {
	active, err := store.LoadActive(routeID)
	if err != nil {
		return "", err
	}
	directory, err := store.generationDir(routeID, active.Generation)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "client.wt"), nil
}

// IdentityPath returns the active generation private identity path.
func (store Store) IdentityPath(routeID string) (string, error) {
	active, err := store.LoadActive(routeID)
	if err != nil {
		return "", err
	}
	directory, err := store.generationDir(routeID, active.Generation)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "identity"), nil
}

// Activate writes active.json after the generation directory exists.
func (store Store) Activate(routeID, generation string) error {
	if err := ValidateRouteID(routeID); err != nil {
		return err
	}
	if err := ValidateGenerationID(generation); err != nil {
		return err
	}
	directory, err := store.generationDir(routeID, generation)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(directory, "client.wt")); err != nil {
		return fmt.Errorf("%w: generation %s is incomplete", ErrInvalidRoute, generation)
	}
	return writeJSONAtomic(filepath.Join(store.Root, routeID, "active.json"), Active{
		Kind:          KindActive,
		SchemaVersion: CurrentSchemaVersion,
		RouteID:       routeID,
		Generation:    generation,
	}, 0o600)
}

// LoadActive reads the selected generation.
func (store Store) LoadActive(routeID string) (Active, error) {
	if err := ValidateRouteID(routeID); err != nil {
		return Active{}, err
	}
	var active Active
	if err := readStrictJSON(filepath.Join(store.Root, routeID, "active.json"), &active); err != nil {
		return Active{}, err
	}
	if active.Kind != KindActive || active.SchemaVersion != CurrentSchemaVersion {
		return Active{}, fmt.Errorf("%w: unsupported active-generation schema", ErrInvalidRoute)
	}
	if active.RouteID != routeID {
		return Active{}, fmt.Errorf("%w: active route id mismatch", ErrInvalidRoute)
	}
	if err := ValidateGenerationID(active.Generation); err != nil {
		return Active{}, err
	}
	return active, nil
}

// ReservePort claims a unique route ID and listen port before invite consumption.
func (store Store) ReservePort(routeID string, listenPort uint16) error {
	if listenPort == 0 {
		return fmt.Errorf("%w: listen port must be a nonzero TCP port", ErrInvalidRoute)
	}
	unlock, err := store.lockRoot()
	if err != nil {
		return err
	}
	defer unlock()
	if existing, loadErr := store.loadReservation(routeID); loadErr == nil &&
		existing.RouteID == routeID && existing.ListenPort == listenPort {
		return nil
	}
	if err := store.Reserve(routeID); err != nil {
		if existing, loadErr := store.loadReservation(routeID); loadErr == nil &&
			existing.RouteID == routeID && existing.ListenPort == listenPort {
			return nil
		}
		return err
	}
	owner, taken, err := store.PortOwner(listenPort)
	if err != nil {
		return err
	}
	if taken && owner != routeID {
		_ = os.RemoveAll(filepath.Join(store.Root, routeID))
		return fmt.Errorf("%w: listen port %d is already reserved by %s", ErrInvalidRoute, listenPort, owner)
	}
	return writeJSONAtomic(filepath.Join(store.Root, routeID, "reservation.json"), Reservation{
		Kind:          KindReservation,
		SchemaVersion: CurrentSchemaVersion,
		RouteID:       routeID,
		ListenPort:    listenPort,
	}, 0o600)
}

func (store Store) lockRoot() (func(), error) {
	if err := os.MkdirAll(store.Root, 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(store.Root, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := grantsession.FlockExclusive(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = grantsession.FlockUnlock(file)
		_ = file.Close()
	}, nil
}

// PortOwner reports which route reserved a listen port.
func (store Store) PortOwner(listenPort uint16) (string, bool, error) {
	routes, err := store.List()
	if err != nil {
		return "", false, err
	}
	want := strconv.FormatUint(uint64(listenPort), 10)
	for _, route := range routes {
		reservation, err := store.loadReservation(route.RouteID)
		if err != nil {
			if route.Listen != "" && listenEndpointPort(route.Listen) == want {
				return route.RouteID, true, nil
			}
			continue
		}
		if reservation.ListenPort == listenPort {
			return route.RouteID, true, nil
		}
	}
	return "", false, nil
}

func (store Store) loadReservation(routeID string) (Reservation, error) {
	var reservation Reservation
	if err := readStrictJSON(filepath.Join(store.Root, routeID, "reservation.json"), &reservation); err != nil {
		return Reservation{}, err
	}
	if reservation.Kind != KindReservation || reservation.SchemaVersion != CurrentSchemaVersion {
		return Reservation{}, fmt.Errorf("%w: unsupported reservation schema", ErrInvalidRoute)
	}
	return reservation, nil
}

func listenEndpointPort(endpoint string) string {
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			return endpoint[i+1:]
		}
	}
	return ""
}
