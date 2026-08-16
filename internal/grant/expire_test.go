package grant

import (
	"fmt"
	"testing"
	"time"
)

func TestExpireRequiresVerifiedSideEffects(t *testing.T) {
	t.Parallel()

	plan := ExpirePlan{
		ClientID:        "abc",
		Generation:      "g1",
		PublicKey:       "key",
		PublicKeySHA256: "digest",
		Status:          StatusActive,
		NotAfter:        time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		Now:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
	}
	if err := ExecuteExpire(plan, ExpireOps{}); err == nil {
		t.Fatal("ExecuteExpire accepted incomplete ops")
	}
	removed := false
	terminated := false
	authGone := false
	sessionGone := false
	burned := false
	err := ExecuteExpire(plan, ExpireOps{
		RemoveAuthorization: func(string) error {
			removed = true
			return nil
		},
		VerifyAuthorizationGone: func(string) error {
			if !removed {
				t.Fatal("verified authorization before removal")
			}
			authGone = true
			return nil
		},
		TerminateSession: func(string, string, string) error {
			terminated = true
			return nil
		},
		VerifySessionGone: func(string, string, string) error {
			if !terminated {
				t.Fatal("verified session before terminate")
			}
			sessionGone = true
			return nil
		},
		BurnManagementToken: func() (string, error) {
			if !authGone || !sessionGone {
				t.Fatal("burned token before verification")
			}
			burned = true
			return "next", nil
		},
	})
	if err != nil {
		t.Fatalf("ExecuteExpire: %v", err)
	}
	if !burned {
		t.Fatal("management token was not burned")
	}
}

func TestExecuteExpireFailsWhenSessionStillEffective(t *testing.T) {
	t.Parallel()

	plan := ExpirePlan{
		ClientID:        "abc",
		Generation:      "g1",
		PublicKey:       "key",
		PublicKeySHA256: "digest",
		Status:          StatusExpirationPending,
		NotAfter:        time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		Now:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
	}
	err := ExecuteExpire(plan, ExpireOps{
		RemoveAuthorization:     func(string) error { return nil },
		VerifyAuthorizationGone: func(string) error { return nil },
		TerminateSession:        func(string, string, string) error { return nil },
		VerifySessionGone:       func(string, string, string) error { return fmt.Errorf("session still effective") },
		BurnManagementToken:     func() (string, error) { t.Fatal("burned before session verify"); return "", nil },
	})
	if err == nil {
		t.Fatal("ExecuteExpire published success while the session remained effective")
	}
}
