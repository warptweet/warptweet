package grant

import (
	"fmt"
	"time"
)

// ExpireOps are the host side effects required to publish expired.
type ExpireOps struct {
	RemoveAuthorization     func(publicKey string) error
	VerifyAuthorizationGone func(publicKey string) error
	TerminateSession        func(clientID, generation, publicKeySHA256 string) error
	VerifySessionGone       func(clientID, generation, publicKeySHA256 string) error
	BurnManagementToken     func() (nextHash string, err error)
}

// ExpirePlan is one serialized expiry transaction for a grant generation.
type ExpirePlan struct {
	ClientID        string
	Generation      string
	PublicKey       string
	PublicKeySHA256 string
	Status          string
	NotAfter        time.Time
	Now             time.Time
}

// ReadyToExpire reports whether the grant's authorization window has ended.
func ReadyToExpire(notAfter, now time.Time) bool {
	if notAfter.IsZero() || now.IsZero() {
		return false
	}
	return !now.UTC().Before(notAfter.UTC())
}

// ValidateExpirePlan checks that expiry may begin or resume.
func ValidateExpirePlan(plan ExpirePlan) error {
	if plan.ClientID == "" || plan.Generation == "" || plan.PublicKey == "" || plan.PublicKeySHA256 == "" {
		return fmt.Errorf("expiry requires client_id, generation, public_key, and public_key_sha256")
	}
	if plan.Now.IsZero() || plan.NotAfter.IsZero() {
		return fmt.Errorf("expiry requires accepted host timestamps")
	}
	if !ReadyToExpire(plan.NotAfter, plan.Now) && plan.Status != StatusExpirationPending {
		return fmt.Errorf("grant %s is not due to expire", plan.ClientID)
	}
	switch plan.Status {
	case StatusActive, StatusExpirationPending, StatusRotationPending:
	default:
		return fmt.Errorf("grant status %q cannot expire", plan.Status)
	}
	return nil
}

// ExecuteExpire runs LEASE-004. It never reports success while the key or
// matching session remains effective. Callers persist expiration_pending
// before invoking this function.
func ExecuteExpire(plan ExpirePlan, ops ExpireOps) error {
	if err := ValidateExpirePlan(plan); err != nil {
		return err
	}
	if err := AuthorizeTransition(plan.Status, StatusExpirationPending); err != nil {
		return err
	}
	if ops.RemoveAuthorization == nil || ops.VerifyAuthorizationGone == nil ||
		ops.TerminateSession == nil || ops.VerifySessionGone == nil ||
		ops.BurnManagementToken == nil {
		return fmt.Errorf("expiry operations are incomplete")
	}
	if err := ops.RemoveAuthorization(plan.PublicKey); err != nil {
		return fmt.Errorf("remove effective authorization: %w", err)
	}
	if err := ops.TerminateSession(plan.ClientID, "", ""); err != nil {
		return fmt.Errorf("terminate matching session: %w", err)
	}
	if err := ops.VerifyAuthorizationGone(plan.PublicKey); err != nil {
		return fmt.Errorf("authorization still effective: %w", err)
	}
	if err := ops.VerifySessionGone(plan.ClientID, "", ""); err != nil {
		return fmt.Errorf("matching session still effective: %w", err)
	}
	if _, err := ops.BurnManagementToken(); err != nil {
		return fmt.Errorf("burn management capability: %w", err)
	}
	return nil
}
