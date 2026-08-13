// Package publicrelease validates the website Homebrew CTA gate against
// package-to-package evidence completeness.
package publicrelease

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"warptweet.com/warptweet/internal/releaseevidence"
)

const (
	// Kind is the public release gate document kind.
	Kind = "warptweet.public-release-gate"
	// SchemaVersion is the only supported gate schema.
	SchemaVersion = 1
	// DefaultHomebrewCommand is the only website-primary install command.
	DefaultHomebrewCommand = "brew install --cask warptweet/tap/warptweet"
	// DefaultNextCommand is the post-install enrollment action.
	DefaultNextCommand = "warptweet enroll <single-use-invite>"
	// QualificationMessage is shown while the CTA remains dark.
	QualificationMessage = "Homebrew package in release qualification"
)

// Gate is the website install activation document.
type Gate struct {
	Kind                     string            `json:"kind"`
	SchemaVersion            int               `json:"schema_version"`
	HomebrewCTAEnabled       bool              `json:"homebrew_cta_enabled"`
	HomebrewCommand          string            `json:"homebrew_command"`
	NextCommand              string            `json:"next_command"`
	QualificationMessage     string            `json:"qualification_message"`
	RequiredEvidenceDocument string            `json:"required_evidence_document"`
	Links                    map[string]string `json:"links"`
	Notes                    []string          `json:"notes"`
}

// LoadGate reads the repository public-release gate.
func LoadGate(path string) (Gate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Gate{}, err
	}
	var gate Gate
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&gate); err != nil {
		return Gate{}, err
	}
	if decoder.More() {
		return Gate{}, fmt.Errorf("trailing JSON values")
	}
	if err := ValidateGate(gate); err != nil {
		return Gate{}, err
	}
	return gate, nil
}

// ValidateGate checks local consistency of the CTA gate document.
func ValidateGate(gate Gate) error {
	if gate.Kind != Kind || gate.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported public release gate kind/version")
	}
	if gate.HomebrewCommand != DefaultHomebrewCommand {
		return fmt.Errorf("homebrew_command must be %q", DefaultHomebrewCommand)
	}
	if gate.NextCommand != DefaultNextCommand {
		return fmt.Errorf("next_command must be %q", DefaultNextCommand)
	}
	if gate.QualificationMessage != QualificationMessage {
		return fmt.Errorf("qualification_message must be %q", QualificationMessage)
	}
	if gate.HomebrewCTAEnabled {
		if strings.TrimSpace(gate.RequiredEvidenceDocument) == "" {
			return fmt.Errorf("enabled CTA requires required_evidence_document")
		}
		if filepath.IsAbs(gate.RequiredEvidenceDocument) {
			return fmt.Errorf("required_evidence_document must be repository-relative")
		}
	}
	return nil
}

// ValidateEnabledCTA ensures an enabled CTA points at complete package evidence.
func ValidateEnabledCTA(repositoryRoot string, gate Gate) error {
	if err := ValidateGate(gate); err != nil {
		return err
	}
	if !gate.HomebrewCTAEnabled {
		return nil
	}
	checklist, err := releaseevidence.LoadChecklist(releaseevidence.DefaultChecklistPath(repositoryRoot))
	if err != nil {
		return err
	}
	evidencePath := filepath.Join(repositoryRoot, gate.RequiredEvidenceDocument)
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		return fmt.Errorf("read required evidence document: %w", err)
	}
	var report releaseevidence.Report
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return fmt.Errorf("decode required evidence document: %w", err)
	}
	if err := releaseevidence.ValidateReport(checklist, report); err != nil {
		return fmt.Errorf("invalid required evidence document: %w", err)
	}
	if !releaseevidence.Complete(report) {
		return fmt.Errorf("required evidence document is incomplete")
	}
	return nil
}

// DefaultGatePath returns the repository public-release gate path.
func DefaultGatePath(repositoryRoot string) string {
	return filepath.Join(repositoryRoot, "packaging", "evidence", "public-release.json")
}
