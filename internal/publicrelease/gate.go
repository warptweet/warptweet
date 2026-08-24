// Package publicrelease validates the website Homebrew CTA gate against
// package-to-package evidence completeness.
package publicrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"warptweet.com/warptweet/internal/releaseevidence"
	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// Kind is the public release gate document kind.
	Kind = "warptweet.public-release-gate"
	// SchemaVersion is the only supported gate schema.
	SchemaVersion = 1
	// DefaultHomebrewCommand is the only website-primary install command.
	DefaultHomebrewCommand = "brew install --cask warptweet/tap/warptweet"
	// DefaultNextCommand is the post-install connect action.
	DefaultNextCommand = "warptweet connect <invite-file>"
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
	if err := strictjson.RejectDuplicateObjectNames(raw); err != nil {
		return Gate{}, err
	}
	var gate Gate
	if err := decodeExactlyOneJSON(raw, &gate); err != nil {
		return Gate{}, err
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
	if checklist, ok := gate.Links["evidence_checklist"]; ok {
		if checklist != "packaging/evidence/checklist-v3.json" {
			return fmt.Errorf("evidence_checklist must be packaging/evidence/checklist-v3.json")
		}
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

// ValidateEnabledCTA ensures an enabled CTA points at a complete v3 index.
func ValidateEnabledCTA(repositoryRoot string, gate Gate) error {
	if err := ValidateGate(gate); err != nil {
		return err
	}
	if !gate.HomebrewCTAEnabled {
		return nil
	}
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(repositoryRoot))
	if err != nil {
		return err
	}
	evidencePath := filepath.Join(repositoryRoot, gate.RequiredEvidenceDocument)
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		return fmt.Errorf("read required evidence document: %w", err)
	}
	if err := strictjson.RejectDuplicateObjectNames(raw); err != nil {
		return fmt.Errorf("invalid required evidence document: %w", err)
	}
	index, err := releaseevidence.DecodeIndexV3(raw)
	if err != nil {
		return fmt.Errorf("decode required evidence index: %w", err)
	}
	if err := releaseevidence.ValidateIndexDocumentV3(checklist, index); err != nil {
		return fmt.Errorf("invalid required evidence index: %w", err)
	}
	for i, report := range index.Reports {
		if report.ClientPackagePath == "" && report.ServerPackagePath == "" {
			continue
		}
		if err := releaseevidence.BindArtifactDigestsV3(repositoryRoot, report); err != nil {
			return fmt.Errorf("evidence artifacts in report %d: %w", i, err)
		}
	}
	if !releaseevidence.CompleteIndexV3(checklist, index.Reports) {
		return fmt.Errorf("required evidence index is incomplete")
	}
	return nil
}

// VerifyRepository authenticates the canonical v3 checklist and keeps the CTA
// dark unless a complete v3 index is supplied.
func VerifyRepository(repositoryRoot string) error {
	gate, err := LoadGate(DefaultGatePath(repositoryRoot))
	if err != nil {
		return err
	}
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(repositoryRoot))
	if err != nil {
		return err
	}
	if checklist.FileSHA256 == "" {
		return fmt.Errorf("canonical checklist is not authenticated")
	}
	if !gate.HomebrewCTAEnabled {
		return nil
	}
	return ValidateEnabledCTA(repositoryRoot, gate)
}

// DefaultGatePath returns the repository public-release gate path.
func DefaultGatePath(repositoryRoot string) string {
	return filepath.Join(repositoryRoot, "packaging", "evidence", "public-release.json")
}

func decodeExactlyOneJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("trailing JSON values")
	}
	return fmt.Errorf("trailing JSON data: %w", err)
}
