package grant

import "testing"

func TestGrantStateMachine(t *testing.T) {
	t.Parallel()

	allowed := [][2]string{
		{StatusActive, StatusActive},
		{StatusExpirationPending, StatusExpirationPending},
		{StatusEnrollmentPending, StatusActive},
		{StatusActive, StatusExpirationPending},
		{StatusExpirationPending, StatusExpired},
		{StatusActive, StatusRotationPending},
		{StatusRotationPending, StatusActive},
		{StatusRotationPending, StatusRevocationPending},
		{StatusRotationPending, StatusExpirationPending},
		{StatusActive, StatusRevocationPending},
		{StatusExpirationPending, StatusRevocationPending},
		{StatusRevocationPending, StatusRevoked},
	}
	for _, pair := range allowed {
		if err := AuthorizeTransition(pair[0], pair[1]); err != nil {
			t.Fatalf("%s -> %s: %v", pair[0], pair[1], err)
		}
	}
	forbidden := [][2]string{
		{"bogus", "bogus"},
		{"bogus", StatusActive},
		{StatusExpired, StatusActive},
		{StatusRevoked, StatusActive},
		{StatusExpired, StatusRevoked},
		{StatusRevoked, StatusExpired},
		{StatusEnrollmentPending, StatusExpired},
		{StatusActive, StatusExpired},
		{StatusRotationPending, StatusExpired},
	}
	for _, pair := range forbidden {
		if err := AuthorizeTransition(pair[0], pair[1]); err == nil {
			t.Fatalf("allowed forbidden transition %s -> %s", pair[0], pair[1])
		}
	}
	if !Terminal(StatusExpired) || !Terminal(StatusRevoked) || Terminal(StatusActive) {
		t.Fatal("terminal classification is wrong")
	}
}
