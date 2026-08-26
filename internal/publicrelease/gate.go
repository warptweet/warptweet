// Package publicrelease validates the website release gate against qualified
// package evidence and, separately, proof that the public install path works.
package publicrelease

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/releaseevidence"
	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// Kind is the public release gate document kind.
	Kind = "warptweet.public-release-gate"
	// SchemaVersion is the only supported gate schema.
	SchemaVersion = 2
	// DistributionKind is the clean-install evidence document kind.
	DistributionKind = "warptweet.public-distribution-evidence"
	// DistributionSchemaVersion is the only supported distribution schema.
	DistributionSchemaVersion = 1
	// DefaultHomebrewCommand is the only website-primary client install command.
	DefaultHomebrewCommand = "brew install --cask warptweet/tap/warptweet"
	// DefaultNextCommand is the post-install connect action.
	DefaultNextCommand = "warptweet connect <invite-file>"
	// QualificationMessage describes complete package and topology qualification.
	QualificationMessage = "First-edition package matrix complete"
	// DistributionMessage describes the state before public packages exist.
	DistributionMessage = "Public packages are being prepared"
)

// Gate separates product qualification from public distribution availability.
type Gate struct {
	Kind                                 string            `json:"kind"`
	SchemaVersion                        int               `json:"schema_version"`
	QualificationComplete                bool              `json:"qualification_complete"`
	PublicDistributionReady              bool              `json:"public_distribution_ready"`
	HomebrewCommand                      string            `json:"homebrew_command"`
	NextCommand                          string            `json:"next_command"`
	QualificationMessage                 string            `json:"qualification_message"`
	DistributionMessage                  string            `json:"distribution_message"`
	RequiredEvidenceDocument             string            `json:"required_evidence_document"`
	RequiredDistributionEvidenceDocument string            `json:"required_distribution_evidence_document"`
	Links                                map[string]string `json:"links"`
	Notes                                []string          `json:"notes"`
}

// DistributionEvidence proves that the advertised public cask installed the
// same qualified client artifact on a clean supported Mac.
type DistributionEvidence struct {
	Kind                string               `json:"kind"`
	SchemaVersion       int                  `json:"schema_version"`
	ReleaseVersion      string               `json:"release_version"`
	SourceCommit        string               `json:"source_commit"`
	GitHubReleaseURL    string               `json:"github_release_url"`
	HomebrewTapURL      string               `json:"homebrew_tap_url"`
	HomebrewTapCommit   string               `json:"homebrew_tap_commit"`
	HomebrewCaskPath    string               `json:"homebrew_cask_path"`
	HomebrewCaskSHA256  string               `json:"homebrew_cask_sha256"`
	ClientPackageSHA256 string               `json:"client_package_sha256"`
	CleanInstall        CleanInstallEvidence `json:"clean_install"`
}

// CleanInstallEvidence records the observed end-user Homebrew path.
type CleanInstallEvidence struct {
	Status                      string `json:"status"`
	Platform                    string `json:"platform"`
	Architecture                string `json:"architecture"`
	Command                     string `json:"command"`
	HomebrewVersion             string `json:"homebrew_version"`
	InstalledVersion            string `json:"installed_version"`
	ObservedClientPackageSHA256 string `json:"observed_client_package_sha256"`
	PerformedAt                 string `json:"performed_at"`
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

// ValidateGate checks the local state-machine invariants of the release gate.
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
	if gate.DistributionMessage != DistributionMessage {
		return fmt.Errorf("distribution_message must be %q", DistributionMessage)
	}
	if gate.Links["evidence_checklist"] != "packaging/evidence/checklist-v3.json" {
		return fmt.Errorf("evidence_checklist must be packaging/evidence/checklist-v3.json")
	}
	if gate.QualificationComplete {
		if err := validateRelativeDocumentPath(gate.RequiredEvidenceDocument, "required_evidence_document"); err != nil {
			return err
		}
	} else {
		if gate.PublicDistributionReady {
			return fmt.Errorf("public distribution requires complete qualification")
		}
		if gate.RequiredEvidenceDocument != "" {
			return fmt.Errorf("qualification evidence must be empty while qualification is incomplete")
		}
	}
	if gate.PublicDistributionReady {
		if err := validateRelativeDocumentPath(gate.RequiredDistributionEvidenceDocument, "required_distribution_evidence_document"); err != nil {
			return err
		}
	} else if gate.RequiredDistributionEvidenceDocument != "" {
		return fmt.Errorf("distribution evidence must be empty while public distribution is not ready")
	}
	return nil
}

// ValidateQualification ensures a qualified gate points at a complete v3 index.
func ValidateQualification(repositoryRoot string, gate Gate) error {
	_, err := loadQualifiedIndex(repositoryRoot, gate)
	return err
}

// ValidatePublicDistribution binds the public cask and clean-install proof to
// the exact non-development artifacts in the qualified v3 evidence index.
func ValidatePublicDistribution(repositoryRoot string, gate Gate) error {
	if err := ValidateGate(gate); err != nil {
		return err
	}
	if !gate.PublicDistributionReady {
		return nil
	}
	index, err := loadQualifiedIndex(repositoryRoot, gate)
	if err != nil {
		return err
	}
	distribution, err := loadDistributionEvidence(filepath.Join(repositoryRoot, gate.RequiredDistributionEvidenceDocument))
	if err != nil {
		return err
	}
	if err := validateDistributionEvidence(distribution); err != nil {
		return err
	}
	for reportIndex, report := range index.Reports {
		if report.ReleaseVersion != distribution.ReleaseVersion {
			return fmt.Errorf("distribution release_version does not match report %d", reportIndex)
		}
		if report.SourceCommit != distribution.SourceCommit {
			return fmt.Errorf("distribution source_commit does not match report %d", reportIndex)
		}
		if report.ClientPackageSHA256 != distribution.ClientPackageSHA256 {
			return fmt.Errorf("distribution client package does not match report %d", reportIndex)
		}
	}
	return nil
}

// VerifyRepository authenticates qualification and keeps the public install
// path dark unless separate distribution evidence is present and valid.
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
	if gate.QualificationComplete {
		if err := ValidateQualification(repositoryRoot, gate); err != nil {
			return err
		}
	}
	return ValidatePublicDistribution(repositoryRoot, gate)
}

func loadQualifiedIndex(repositoryRoot string, gate Gate) (releaseevidence.IndexV3, error) {
	if err := ValidateGate(gate); err != nil {
		return releaseevidence.IndexV3{}, err
	}
	if !gate.QualificationComplete {
		return releaseevidence.IndexV3{}, fmt.Errorf("package qualification is incomplete")
	}
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(repositoryRoot))
	if err != nil {
		return releaseevidence.IndexV3{}, err
	}
	evidencePath := filepath.Join(repositoryRoot, gate.RequiredEvidenceDocument)
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		return releaseevidence.IndexV3{}, fmt.Errorf("read required evidence document: %w", err)
	}
	if err := strictjson.RejectDuplicateObjectNames(raw); err != nil {
		return releaseevidence.IndexV3{}, fmt.Errorf("invalid required evidence document: %w", err)
	}
	index, err := releaseevidence.DecodeIndexV3(raw)
	if err != nil {
		return releaseevidence.IndexV3{}, fmt.Errorf("decode required evidence index: %w", err)
	}
	if err := releaseevidence.ValidateIndexDocumentV3(checklist, index); err != nil {
		return releaseevidence.IndexV3{}, fmt.Errorf("invalid required evidence index: %w", err)
	}
	for reportIndex, report := range index.Reports {
		if report.ClientPackagePath == "" && report.ServerPackagePath == "" {
			continue
		}
		if err := releaseevidence.BindArtifactDigestsV3(repositoryRoot, report); err != nil {
			return releaseevidence.IndexV3{}, fmt.Errorf("evidence artifacts in report %d: %w", reportIndex, err)
		}
	}
	if err := releaseevidence.IndexCompletenessError(checklist, index.Reports); err != nil {
		return releaseevidence.IndexV3{}, fmt.Errorf("required evidence index is incomplete: %w", err)
	}
	return index, nil
}

func loadDistributionEvidence(path string) (DistributionEvidence, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return DistributionEvidence{}, fmt.Errorf("read distribution evidence: %w", err)
	}
	if err := strictjson.RejectDuplicateObjectNames(raw); err != nil {
		return DistributionEvidence{}, fmt.Errorf("invalid distribution evidence: %w", err)
	}
	var evidence DistributionEvidence
	if err := decodeExactlyOneJSON(raw, &evidence); err != nil {
		return DistributionEvidence{}, fmt.Errorf("decode distribution evidence: %w", err)
	}
	return evidence, nil
}

func validateDistributionEvidence(evidence DistributionEvidence) error {
	if evidence.Kind != DistributionKind || evidence.SchemaVersion != DistributionSchemaVersion {
		return fmt.Errorf("unsupported public distribution evidence kind/version")
	}
	if strings.TrimSpace(evidence.ReleaseVersion) == "" || strings.Contains(strings.ToLower(evidence.ReleaseVersion), "dev") {
		return fmt.Errorf("distribution release_version must be non-development")
	}
	if !isHexLength(evidence.SourceCommit, 20) || !isHexLength(evidence.HomebrewTapCommit, 20) {
		return fmt.Errorf("distribution commits must be 40 lowercase hex characters")
	}
	if !isHTTPSURLUnder(evidence.GitHubReleaseURL, "github.com", "/warptweet/warptweet/releases/") {
		return fmt.Errorf("github_release_url must identify a warptweet/warptweet GitHub release")
	}
	if evidence.HomebrewTapURL != "https://github.com/warptweet/homebrew-tap" {
		return fmt.Errorf("homebrew_tap_url must identify the first-party WarpTweet tap")
	}
	if evidence.HomebrewCaskPath != "Casks/warptweet.rb" {
		return fmt.Errorf("homebrew_cask_path must be Casks/warptweet.rb")
	}
	if !isHexLength(evidence.HomebrewCaskSHA256, 32) || !isHexLength(evidence.ClientPackageSHA256, 32) {
		return fmt.Errorf("distribution digests must be SHA-256")
	}
	install := evidence.CleanInstall
	if install.Status != "pass" || install.Platform != "darwin" || install.Architecture != "arm64" {
		return fmt.Errorf("clean install must pass on darwin-arm64")
	}
	if install.Command != DefaultHomebrewCommand {
		return fmt.Errorf("clean install command must be %q", DefaultHomebrewCommand)
	}
	if strings.TrimSpace(install.HomebrewVersion) == "" || install.InstalledVersion != evidence.ReleaseVersion {
		return fmt.Errorf("clean install versions are incomplete or inconsistent")
	}
	if install.ObservedClientPackageSHA256 != evidence.ClientPackageSHA256 {
		return fmt.Errorf("clean install client digest does not match distribution")
	}
	if _, err := time.Parse(time.RFC3339, install.PerformedAt); err != nil {
		return fmt.Errorf("clean install performed_at must be RFC3339: %w", err)
	}
	return nil
}

func validateRelativeDocumentPath(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	clean := filepath.Clean(value)
	if filepath.IsAbs(value) || clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s must be a canonical repository-relative path", field)
	}
	return nil
}

func isHexLength(value string, byteLength int) bool {
	if value != strings.ToLower(value) || len(value) != byteLength*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
}

func isHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" && parsed.RawQuery == ""
}

func isHTTPSURLUnder(value, host, pathPrefix string) bool {
	if !isHTTPSURL(value) {
		return false
	}
	parsed, _ := url.Parse(value)
	return parsed.Host == host && strings.HasPrefix(parsed.EscapedPath(), pathPrefix)
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
