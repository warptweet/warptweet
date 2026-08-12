//go:build !linux && !darwin

package engine

import (
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
)

func TestProductionClientStateValidationFailsClosedOffLinuxAndDarwin(t *testing.T) {
	t.Parallel()

	_, err := LoadProductionClientManifest(installlayout.ClientManifestPath)
	if err == nil || !strings.Contains(err.Error(), "requires Linux or Darwin") {
		t.Fatalf("LoadProductionClientManifest error = %v, want unsupported-platform rejection", err)
	}
	if _, err := ValidateAssets(validClientSpec(t)); err == nil ||
		!strings.Contains(err.Error(), "requires Linux or Darwin") {
		t.Fatalf("ValidateAssets error = %v, want unsupported-platform rejection", err)
	}
}
