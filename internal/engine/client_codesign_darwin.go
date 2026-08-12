//go:build darwin

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func verifyProductionClientCodeSignaturePlatform(path string) error {
	if path == "" {
		return errors.New("code signature path is required")
	}
	if productionCodeSigningTeamID == "" {
		return errors.New("production client code-signing Team ID is not configured")
	}

	verify := exec.Command("codesign", "--verify", "--deep", "--strict", "--verbose=2", path)
	verify.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := verify.CombinedOutput(); err != nil {
		return fmt.Errorf("codesign verify failed for %q: %w (%s)", path, err, strings.TrimSpace(string(output)))
	}

	display := exec.Command("codesign", "--display", "--verbose=2", path)
	display.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := display.CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign display failed for %q: %w (%s)", path, err, strings.TrimSpace(string(output)))
	}
	teamLine := "TeamIdentifier=" + productionCodeSigningTeamID
	if !bytes.Contains(output, []byte(teamLine)) {
		return fmt.Errorf(
			"OpenSSH executable %q is not signed by required Team ID %q",
			path,
			productionCodeSigningTeamID,
		)
	}
	return nil
}
