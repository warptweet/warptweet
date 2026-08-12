//go:build !linux && !darwin

package engine

import (
	"context"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
)

func TestProductionClientPreflightFailsClosedOffLinuxAndDarwin(t *testing.T) {
	t.Parallel()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	_, err = Preflight(context.Background(), Binary{
		Path:   installlayout.SSHPath,
		SHA256: strings.Repeat("0", 64),
	}, selected)
	if err == nil ||
		(!strings.Contains(err.Error(), "requires Linux or Darwin") &&
			!strings.Contains(err.Error(), "not supported for production client preflight") &&
			!strings.Contains(err.Error(), "unsupported platform artifact profile")) {
		t.Fatalf("Preflight error = %v, want unsupported-platform rejection", err)
	}
}
