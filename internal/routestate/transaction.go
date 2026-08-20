package routestate

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	KindTransaction = "warptweet.route-transaction"

	PhaseReserved         = "reserved"
	PhaseStaged           = "staged"
	PhaseEnrolled         = "enrolled"
	PhaseActivating       = "activating"
	PhaseConnected        = "connected"
	PhaseEnrolledNotReady = "enrolled_not_ready"
	PhaseFailed           = "failed"
)

// Transaction is the durable connect-state record for one route.
type Transaction struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
	RouteID       string `json:"route_id"`
	Phase         string `json:"phase"`
	ListenPort    uint16 `json:"listen_port,omitempty"`
	Generation    string `json:"generation,omitempty"`
	InviteID      string `json:"invite_id,omitempty"`
	Error         string `json:"error,omitempty"`
	UpdatedAt     string `json:"updated_at"`
}

func (store Store) transactionPath(routeID string) (string, error) {
	if err := ValidateRouteID(routeID); err != nil {
		return "", err
	}
	return filepath.Join(store.Root, routeID, "transaction.json"), nil
}

// WriteTransaction persists one connect-state transition.
func (store Store) WriteTransaction(transaction Transaction) error {
	if err := ValidateRouteID(transaction.RouteID); err != nil {
		return err
	}
	if err := validateTransactionPhase(transaction.Phase); err != nil {
		return err
	}
	transaction.Kind = KindTransaction
	transaction.SchemaVersion = CurrentSchemaVersion
	if transaction.UpdatedAt == "" {
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	path, err := store.transactionPath(transaction.RouteID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeJSONAtomic(path, transaction, 0o640)
}

// ReserveAndWriteTransaction claims the listen port and persists PhaseReserved
// under one root lock. A transaction write failure releases the reservation.
func (store Store) ReserveAndWriteTransaction(transaction Transaction) error {
	if transaction.Phase != PhaseReserved {
		return fmt.Errorf("%w: reserve-and-write requires phase %q", ErrInvalidRoute, PhaseReserved)
	}
	if err := ValidateRouteID(transaction.RouteID); err != nil {
		return err
	}
	if err := validateTransactionPhase(transaction.Phase); err != nil {
		return err
	}
	unlock, err := store.lockRoot()
	if err != nil {
		return err
	}
	defer unlock()
	created, err := store.reservePortLocked(transaction.RouteID, transaction.ListenPort)
	if err != nil {
		return err
	}
	if err := store.WriteTransaction(transaction); err != nil {
		if created {
			_ = store.releaseReservationLocked(transaction.RouteID)
		}
		return err
	}
	return nil
}

// LoadTransaction reads the connect-state record.
func (store Store) LoadTransaction(routeID string) (Transaction, error) {
	path, err := store.transactionPath(routeID)
	if err != nil {
		return Transaction{}, err
	}
	var transaction Transaction
	if err := readStrictJSON(path, &transaction); err != nil {
		return Transaction{}, err
	}
	if transaction.Kind != KindTransaction || transaction.SchemaVersion != CurrentSchemaVersion {
		return Transaction{}, fmt.Errorf("%w: unsupported transaction schema", ErrInvalidRoute)
	}
	if transaction.RouteID != routeID {
		return Transaction{}, fmt.Errorf("%w: transaction route id mismatch", ErrInvalidRoute)
	}
	if err := validateTransactionPhase(transaction.Phase); err != nil {
		return Transaction{}, err
	}
	return transaction, nil
}

func validateTransactionPhase(phase string) error {
	switch phase {
	case PhaseReserved, PhaseStaged, PhaseEnrolled, PhaseActivating, PhaseConnected, PhaseEnrolledNotReady, PhaseFailed:
		return nil
	default:
		return fmt.Errorf("%w: unsupported transaction phase %q", ErrInvalidRoute, phase)
	}
}
