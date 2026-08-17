// Package routestate is the durable client desired-state authority for
// independently enrolled routes. Runtime state.json is observation only.
package routestate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/strictjson"
)

const (
	KindDesiredState     = "warptweet.route-desired-state"
	CurrentSchemaVersion = 1

	DesiredRunning = "running"
	DesiredStopped = "stopped"

	RestartUnlessStopped = "unless-stopped"
	RestartManual        = "manual"

	maxRouteDocumentBytes = 16 << 10
)

// ErrInvalidRoute identifies a route ID or desired-state document that fails closed.
var ErrInvalidRoute = errors.New("invalid WarpTweet route")

// Intent is the durable desired-state record for one route.
type Intent struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
	RouteID       string `json:"route_id"`
	DesiredState  string `json:"desired_state"`
	RestartPolicy string `json:"restart_policy"`
	BootID        string `json:"boot_id,omitempty"`
	UpdatedAt     string `json:"updated_at"`
}

// Receipt is the host-acknowledged enrollment copy retained per route.
type Receipt struct {
	InviteID                     string `json:"invite_id"`
	ClientID                     string `json:"client_id"`
	GrantID                      string `json:"grant_id,omitempty"`
	RouteID                      string `json:"route_id"`
	AcceptedAt                   string `json:"accepted_at"`
	AuthorizationNotAfter        string `json:"authorization_not_after"`
	AuthorizationDurationSeconds int64  `json:"authorization_duration_seconds"`
	Generation                   string `json:"generation"`
	ManagementToken              string `json:"management_token,omitempty"`
	ServerAddress                string `json:"server_address"`
	EnrollPort                   uint16 `json:"enroll_port,omitempty"`
	PublicKey                    string `json:"public_key,omitempty"`
	HostPublicKey                string `json:"host_public_key,omitempty"`
	EnrollmentTLSSPKISHA256      string `json:"enrollment_tls_spki_sha256"`
	Target                       string `json:"target,omitempty"`
	ListenEndpoint               string `json:"listen_endpoint,omitempty"`
	Principal                    string `json:"principal,omitempty"`
	ProfileID                    string `json:"profile_id,omitempty"`
	RevokedAt                    string `json:"revoked_at,omitempty"`
}

// ListedRoute is one enumeration result. Invalid routes remain visible.
type ListedRoute struct {
	RouteID string
	Intent  Intent
	Receipt Receipt
	Invalid bool
	Error   string
	Root    string
	Listen  string
}

// ValidateRouteID rejects path traversal and unsafe service labels.
func ValidateRouteID(routeID string) error {
	if routeID == "" || len(routeID) > 64 {
		return fmt.Errorf("%w: route id must be 1-64 characters", ErrInvalidRoute)
	}
	if strings.Contains(routeID, "..") || strings.ContainsAny(routeID, "/\\:") {
		return fmt.Errorf("%w: route id must not contain path characters", ErrInvalidRoute)
	}
	for i, r := range routeID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
			if i == 0 {
				return fmt.Errorf("%w: route id must start with an alphanumeric character", ErrInvalidRoute)
			}
		default:
			return fmt.Errorf("%w: route id contains forbidden character %q", ErrInvalidRoute, r)
		}
	}
	return nil
}

// ParseRestartPolicy accepts the public restart policies.
func ParseRestartPolicy(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", RestartUnlessStopped:
		return RestartUnlessStopped, nil
	case RestartManual:
		return RestartManual, nil
	default:
		return "", fmt.Errorf("%w: restart policy must be unless-stopped or manual", ErrInvalidRoute)
	}
}

// ShouldStartAtBoot reports whether reconciler should start the route.
func ShouldStartAtBoot(intent Intent, currentBootID string) bool {
	if intent.DesiredState != DesiredRunning {
		return false
	}
	switch intent.RestartPolicy {
	case RestartUnlessStopped:
		return true
	case RestartManual:
		return intent.BootID != "" && intent.BootID == currentBootID
	default:
		return false
	}
}

// ValidateIntent checks one complete desired-state document.
func ValidateIntent(intent Intent) error {
	if intent.Kind != KindDesiredState || intent.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("%w: unsupported desired-state schema", ErrInvalidRoute)
	}
	if err := ValidateRouteID(intent.RouteID); err != nil {
		return err
	}
	if intent.DesiredState != DesiredRunning && intent.DesiredState != DesiredStopped {
		return fmt.Errorf("%w: desired_state must be running or stopped", ErrInvalidRoute)
	}
	if _, err := ParseRestartPolicy(intent.RestartPolicy); err != nil {
		return err
	}
	if intent.RestartPolicy == RestartManual && intent.DesiredState == DesiredRunning && intent.BootID == "" {
		return fmt.Errorf("%w: manual running routes require a boot identity", ErrInvalidRoute)
	}
	return nil
}

// Store is a package-owned route root.
type Store struct {
	Root string
}

func (store Store) routeDir(routeID string) (string, error) {
	if err := ValidateRouteID(routeID); err != nil {
		return "", err
	}
	return filepath.Join(store.Root, routeID), nil
}

func (store Store) intentPath(routeID string) (string, error) {
	directory, err := store.routeDir(routeID)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "desired.json"), nil
}

func (store Store) receiptPath(routeID string) (string, error) {
	directory, err := store.routeDir(routeID)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "receipt.json"), nil
}

// Exists reports whether a route directory is already reserved.
func (store Store) Exists(routeID string) (bool, error) {
	directory, err := store.routeDir(routeID)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: route path is not a directory", ErrInvalidRoute)
	}
	return true, nil
}

// Reserve creates an empty route directory without overwriting an existing one.
func (store Store) Reserve(routeID string) error {
	directory, err := store.routeDir(routeID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(store.Root, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o750); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: route %q already exists", ErrInvalidRoute, routeID)
		}
		return err
	}
	return nil
}

// WriteIntent persists desired state atomically.
func (store Store) WriteIntent(intent Intent) error {
	if intent.UpdatedAt == "" {
		intent.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := ValidateIntent(intent); err != nil {
		return err
	}
	path, err := store.intentPath(intent.RouteID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSONAtomic(path, intent, 0o600)
}

// LoadIntent reads one desired-state document.
func (store Store) LoadIntent(routeID string) (Intent, error) {
	path, err := store.intentPath(routeID)
	if err != nil {
		return Intent{}, err
	}
	var intent Intent
	if err := readStrictJSON(path, &intent); err != nil {
		return Intent{}, err
	}
	if intent.RouteID == "" {
		intent.RouteID = routeID
	}
	if err := ValidateIntent(intent); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

// ValidateReceipt checks required host-acknowledged receipt fields.
func ValidateReceipt(receipt Receipt) error {
	if err := ValidateRouteID(receipt.RouteID); err != nil {
		return err
	}
	if receipt.ClientID == "" || receipt.AuthorizationNotAfter == "" || receipt.AuthorizationDurationSeconds <= 0 || receipt.Generation == "" {
		return fmt.Errorf("%w: receipt is missing required authorization fields", ErrInvalidRoute)
	}
	return nil
}

// WriteReceipt persists the host-acknowledged enrollment copy.
func (store Store) WriteReceipt(receipt Receipt) error {
	if err := ValidateReceipt(receipt); err != nil {
		return err
	}
	path, err := store.receiptPath(receipt.RouteID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSONAtomic(path, receipt, 0o600)
}

// LoadReceipt reads one enrollment receipt.
func (store Store) LoadReceipt(routeID string) (Receipt, error) {
	path, err := store.receiptPath(routeID)
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err := readStrictJSON(path, &receipt); err != nil {
		return Receipt{}, err
	}
	if receipt.RouteID == "" {
		receipt.RouteID = routeID
	}
	return receipt, nil
}

// List enumerates route directories and reports malformed routes without hiding others.
func (store Store) List() ([]ListedRoute, error) {
	entries, err := os.ReadDir(store.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var routes []ListedRoute
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		listed := ListedRoute{RouteID: entry.Name(), Root: filepath.Join(store.Root, entry.Name())}
		if !entry.IsDir() {
			listed.Invalid = true
			listed.Error = "route path is not a directory"
			routes = append(routes, listed)
			continue
		}
		if err := ValidateRouteID(entry.Name()); err != nil {
			listed.Invalid = true
			listed.Error = err.Error()
			routes = append(routes, listed)
			continue
		}
		intent, err := store.LoadIntent(entry.Name())
		if err != nil {
			listed.Invalid = true
			listed.Error = err.Error()
			routes = append(routes, listed)
			continue
		}
		listed.Intent = intent
		receipt, receiptErr := store.LoadReceipt(entry.Name())
		if receiptErr != nil {
			if os.IsNotExist(receiptErr) {
				routes = append(routes, listed)
				continue
			}
			listed.Invalid = true
			listed.Error = receiptErr.Error()
			routes = append(routes, listed)
			continue
		}
		if err := ValidateReceipt(receipt); err != nil {
			listed.Invalid = true
			listed.Error = err.Error()
			routes = append(routes, listed)
			continue
		}
		listed.Receipt = receipt
		listed.Listen = receipt.ListenEndpoint
		routes = append(routes, listed)
	}
	return routes, nil
}

func readStrictJSON(path string, destination any) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(contents) == 0 || len(contents) > maxRouteDocumentBytes {
		return fmt.Errorf("%w: route document is empty or oversized", ErrInvalidRoute)
	}
	if err := strictjson.RejectDuplicateObjectNames(contents); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRoute, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRoute, err)
	}
	if decoder.More() {
		return fmt.Errorf("%w: trailing JSON values", ErrInvalidRoute)
	}
	return nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	contents, err := json.Marshal(value)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".wt-route-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err := temp.Write(contents); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}
