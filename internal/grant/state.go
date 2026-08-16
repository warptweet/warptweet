package grant

import (
	"fmt"
)

// Persisted grant status wire values.
const (
	// StatusEnrollmentPending is a grant that has not yet been activated.
	StatusEnrollmentPending = "enrollment_pending"
	// StatusActive is a grant whose authorization is currently effective.
	StatusActive = "active"
	// StatusExpirationPending is a grant whose expiry transaction is in progress.
	StatusExpirationPending = "expiration_pending"
	// StatusExpired is a terminal grant whose authorization has ended.
	StatusExpired = "expired"
	// StatusRotationPending is a grant whose key rotation is in progress.
	StatusRotationPending = "rotation_pending"
	// StatusRevocationPending is a grant whose revocation is in progress.
	StatusRevocationPending = "revocation_pending"
	// StatusRevoked is a terminal grant that was revoked.
	StatusRevoked = "revoked"
)

var knownStatuses = map[string]struct{}{
	StatusEnrollmentPending: {},
	StatusActive:            {},
	StatusExpirationPending: {},
	StatusExpired:           {},
	StatusRotationPending:   {},
	StatusRevocationPending: {},
	StatusRevoked:           {},
}

// Known reports whether status is a defined grant status.
func Known(status string) bool {
	_, ok := knownStatuses[status]
	return ok
}

// Terminal reports whether status is a terminal grant state.
func Terminal(status string) bool {
	return status == StatusExpired || status == StatusRevoked
}

// CanTransition reports whether from -> to is an allowed grant mutation.
func CanTransition(from, to string) bool {
	if from == to {
		return Known(from)
	}
	switch from {
	case StatusEnrollmentPending:
		return to == StatusActive
	case StatusActive:
		return to == StatusExpirationPending || to == StatusRotationPending || to == StatusRevocationPending
	case StatusExpirationPending:
		return to == StatusExpired || to == StatusRevocationPending
	case StatusRotationPending:
		return to == StatusActive || to == StatusRevocationPending || to == StatusExpirationPending
	case StatusRevocationPending:
		return to == StatusRevoked
	default:
		return false
	}
}

// AuthorizeTransition fails closed on a conflicting grant mutation.
func AuthorizeTransition(from, to string) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("grant status %q cannot transition to %q", from, to)
	}
	return nil
}
