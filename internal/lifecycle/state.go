// Package lifecycle tracks local tunnel process state for user-facing commands.
// Readiness remains separate from target health.
package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Phase is one typed tunnel lifecycle value.
type Phase string

const (
	PhasePreparing         Phase = "Preparing"
	PhaseStarting          Phase = "Starting"
	PhaseAwaitingReadiness Phase = "AwaitingReadiness"
	PhaseReady             Phase = "Ready"
	PhaseBackoff           Phase = "Backoff"
	PhaseStopping          Phase = "Stopping"
	PhaseStopped           Phase = "Stopped"
	PhaseFailed            Phase = "Failed"
)

// TargetHealthNotChecked is the only default target-health value.
const TargetHealthNotChecked = "not_checked"

// State is durable non-secret tunnel lifecycle evidence.
type State struct {
	TunnelID       string `json:"tunnel_id"`
	Phase          Phase  `json:"phase"`
	PID            int    `json:"pid,omitempty"`
	ListenEndpoint string `json:"listen_endpoint,omitempty"`
	TargetHealth   string `json:"target_health"`
	UpdatedAt      string `json:"updated_at"`
	Error          string `json:"error,omitempty"`
	Generation     string `json:"generation,omitempty"`
}

// Store manages per-tunnel state and lock files under a runtime root.
type Store struct {
	Root string
}

func (store Store) tunnelDir(tunnelID string) string {
	return filepath.Join(store.Root, tunnelID)
}

func (store Store) statePath(tunnelID string) string {
	return filepath.Join(store.tunnelDir(tunnelID), "state.json")
}

func (store Store) lockPath(tunnelID string) string {
	return filepath.Join(store.tunnelDir(tunnelID), "lock")
}

func (store Store) pidPath(tunnelID string) string {
	return filepath.Join(store.tunnelDir(tunnelID), "pid")
}

// Lock acquires an exclusive advisory lock for one tunnel.
func (store Store) Lock(tunnelID string) (*os.File, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(store.tunnelDir(tunnelID), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(store.lockPath(tunnelID), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("tunnel %q is busy: %w", tunnelID, err)
	}
	return file, nil
}

// Unlock releases a lock file.
func Unlock(file *os.File) error {
	if file == nil {
		return nil
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return file.Close()
}

// Write persists one complete state document atomically.
func (store Store) Write(state State) error {
	if err := validateTunnelID(state.TunnelID); err != nil {
		return err
	}
	if state.TargetHealth == "" {
		state.TargetHealth = TargetHealthNotChecked
	}
	if state.UpdatedAt == "" {
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := os.MkdirAll(store.tunnelDir(state.TunnelID), 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	path := store.statePath(state.TunnelID)
	temp, err := os.CreateTemp(store.tunnelDir(state.TunnelID), ".state-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err := temp.Write(encoded); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o600); err != nil {
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
	if state.PID > 0 {
		return os.WriteFile(store.pidPath(state.TunnelID), []byte(strconv.Itoa(state.PID)+"\n"), 0o600)
	}
	_ = os.Remove(store.pidPath(state.TunnelID))
	return nil
}

// Read loads tunnel state and refreshes liveness from the process table.
func (store Store) Read(tunnelID string) (State, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return State{}, err
	}
	contents, err := os.ReadFile(store.statePath(tunnelID))
	if err != nil {
		if os.IsNotExist(err) {
			return State{
				TunnelID:     tunnelID,
				Phase:        PhaseStopped,
				TargetHealth: TargetHealthNotChecked,
				UpdatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
			}, nil
		}
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(contents, &state); err != nil {
		return State{}, err
	}
	if state.PID > 0 && !processAlive(state.PID) {
		if state.Phase == PhaseReady || state.Phase == PhaseStarting || state.Phase == PhaseAwaitingReadiness {
			state.Phase = PhaseFailed
			state.Error = "process exited"
			state.PID = 0
		}
	}
	if state.TargetHealth == "" {
		state.TargetHealth = TargetHealthNotChecked
	}
	return state, nil
}

// List returns states for all tunnels with state files.
func (store Store) List() ([]State, error) {
	entries, err := os.ReadDir(store.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var states []State
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		state, err := store.Read(entry.Name())
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, nil
}

// Signal sends a signal to the recorded PID when alive.
func (store Store) Signal(tunnelID string, signal syscall.Signal) error {
	state, err := store.Read(tunnelID)
	if err != nil {
		return err
	}
	if state.PID <= 0 {
		return errors.New("no running process")
	}
	process, err := os.FindProcess(state.PID)
	if err != nil {
		return err
	}
	return process.Signal(signal)
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func validateTunnelID(tunnelID string) error {
	if tunnelID == "" || len(tunnelID) > 64 {
		return errors.New("tunnel id must be 1-64 characters")
	}
	for i, r := range tunnelID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
			if i == 0 {
				return errors.New("tunnel id must start with an alphanumeric character")
			}
		default:
			return fmt.Errorf("tunnel id contains forbidden character %q", r)
		}
	}
	if strings.Contains(tunnelID, "..") {
		return errors.New("tunnel id must not contain ..")
	}
	return nil
}
