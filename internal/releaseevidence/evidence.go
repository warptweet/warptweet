// Package releaseevidence validates package-to-package release evidence
// documents against the immutable checklist.
package releaseevidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// Kind is the release evidence document kind.
	Kind = "warptweet.release-evidence"
	// ChecklistKind is the checklist document kind.
	ChecklistKind = "warptweet.release-evidence-checklist"
	// SchemaVersion is the only supported evidence schema.
	SchemaVersion = 1
)

// Case is one positive or negative evidence requirement.
type Case struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Matrix describes required client/server architecture coverage.
type Matrix struct {
	ClientArtifactProfiles []string `json:"client_artifact_profiles"`
	ServerArtifactProfiles []string `json:"server_artifact_profiles"`
	Note                   string   `json:"note"`
}

// Checklist is the immutable set of required package-interop cases.
type Checklist struct {
	Kind                     string   `json:"kind"`
	SchemaVersion            int      `json:"schema_version"`
	ProfileID                string   `json:"profile_id"`
	RequiresPackageToPackage bool     `json:"requires_package_to_package"`
	ForbidsSourceTreeSubst   bool     `json:"forbids_source_tree_substitution"`
	Positive                 []Case   `json:"positive"`
	Negative                 []Case   `json:"negative"`
	ArtifactBindingFields    []string `json:"artifact_binding_fields"`
	Matrix                   Matrix   `json:"matrix"`
}

// Result is one executed checklist case.
type Result struct {
	ID     string `json:"id"`
	Class  string `json:"class"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report is one package-to-package evidence artifact.
type Report struct {
	Kind                       string   `json:"kind"`
	SchemaVersion              int      `json:"schema_version"`
	ReleaseVersion             string   `json:"release_version"`
	SourceCommit               string   `json:"source_commit"`
	ClientPackageSHA256        string   `json:"client_package_sha256"`
	ServerPackageSHA256        string   `json:"server_package_sha256"`
	ClientArtifactProfileID    string   `json:"client_artifact_profile_id"`
	ServerArtifactProfileID    string   `json:"server_artifact_profile_id"`
	ClientEngineManifestSHA256 string   `json:"client_engine_manifest_sha256"`
	ServerEngineManifestSHA256 string   `json:"server_engine_manifest_sha256"`
	ClientPlatform             string   `json:"client_platform"`
	ServerPlatform             string   `json:"server_platform"`
	ClientArchitecture         string   `json:"client_architecture"`
	ServerArchitecture         string   `json:"server_architecture"`
	TestIdentity               string   `json:"test_identity"`
	Commands                   []string `json:"commands"`
	StartedAt                  string   `json:"started_at"`
	FinishedAt                 string   `json:"finished_at"`
	RedactedLogPath            string   `json:"redacted_log_path,omitempty"`
	PackageToPackage           bool     `json:"package_to_package"`
	SourceTreeSubstitution     bool     `json:"source_tree_substitution"`
	Results                    []Result `json:"results"`
}

// LoadChecklist reads the repository checklist document.
func LoadChecklist(path string) (Checklist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Checklist{}, err
	}
	var checklist Checklist
	if err := decodeStrict(raw, &checklist); err != nil {
		return Checklist{}, err
	}
	if checklist.Kind != ChecklistKind || checklist.SchemaVersion != SchemaVersion {
		return Checklist{}, fmt.Errorf("unsupported checklist kind/version")
	}
	if !checklist.RequiresPackageToPackage || !checklist.ForbidsSourceTreeSubst {
		return Checklist{}, fmt.Errorf("checklist must require package-to-package evidence")
	}
	if len(checklist.Positive) == 0 || len(checklist.Negative) == 0 {
		return Checklist{}, fmt.Errorf("checklist must include positive and negative cases")
	}
	return checklist, nil
}

// ValidateReport checks one evidence report against the checklist.
func ValidateReport(checklist Checklist, report Report) error {
	if report.Kind != Kind || report.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported evidence kind/version")
	}
	if !report.PackageToPackage {
		return fmt.Errorf("evidence must be package-to-package")
	}
	if report.SourceTreeSubstitution {
		return fmt.Errorf("source-tree substitution is forbidden")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"release_version", report.ReleaseVersion},
		{"source_commit", report.SourceCommit},
		{"client_package_sha256", report.ClientPackageSHA256},
		{"server_package_sha256", report.ServerPackageSHA256},
		{"client_artifact_profile_id", report.ClientArtifactProfileID},
		{"server_artifact_profile_id", report.ServerArtifactProfileID},
		{"client_engine_manifest_sha256", report.ClientEngineManifestSHA256},
		{"server_engine_manifest_sha256", report.ServerEngineManifestSHA256},
		{"client_platform", report.ClientPlatform},
		{"server_platform", report.ServerPlatform},
		{"client_architecture", report.ClientArchitecture},
		{"server_architecture", report.ServerArchitecture},
		{"test_identity", report.TestIdentity},
		{"started_at", report.StartedAt},
		{"finished_at", report.FinishedAt},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("missing binding field %s", field.name)
		}
	}
	if len(report.SourceCommit) != 40 || !isLowerHex(report.SourceCommit) {
		return fmt.Errorf("source_commit must be 40 lowercase hex characters")
	}
	for _, digest := range []string{
		report.ClientPackageSHA256,
		report.ServerPackageSHA256,
		report.ClientEngineManifestSHA256,
		report.ServerEngineManifestSHA256,
	} {
		if len(digest) != 64 || !isLowerHex(digest) {
			return fmt.Errorf("package and engine digests must be 64 lowercase hex characters")
		}
	}
	if len(report.Commands) == 0 {
		return fmt.Errorf("commands must be non-empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.StartedAt); err != nil {
		if _, err2 := time.Parse(time.RFC3339, report.StartedAt); err2 != nil {
			return fmt.Errorf("started_at must be RFC3339: %v", err)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, report.FinishedAt); err != nil {
		if _, err2 := time.Parse(time.RFC3339, report.FinishedAt); err2 != nil {
			return fmt.Errorf("finished_at must be RFC3339: %v", err)
		}
	}

	required := map[string]string{}
	for _, item := range checklist.Positive {
		required[item.ID] = "positive"
	}
	for _, item := range checklist.Negative {
		required[item.ID] = "negative"
	}
	seen := map[string]Result{}
	for _, result := range report.Results {
		class, ok := required[result.ID]
		if !ok {
			return fmt.Errorf("unknown result id %q", result.ID)
		}
		if result.Class != class {
			return fmt.Errorf("result %q class %q does not match checklist %q", result.ID, result.Class, class)
		}
		switch result.Status {
		case "pass", "fail", "not_run":
		default:
			return fmt.Errorf("result %q has invalid status %q", result.ID, result.Status)
		}
		if _, exists := seen[result.ID]; exists {
			return fmt.Errorf("duplicate result id %q", result.ID)
		}
		seen[result.ID] = result
	}
	if len(seen) != len(required) {
		missing := make([]string, 0, len(required))
		for id := range required {
			if _, ok := seen[id]; !ok {
				missing = append(missing, id)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("missing checklist results: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Complete reports whether every checklist case passed.
func Complete(report Report) bool {
	if len(report.Results) == 0 {
		return false
	}
	for _, result := range report.Results {
		if result.Status != "pass" {
			return false
		}
	}
	return report.PackageToPackage && !report.SourceTreeSubstitution
}

// DefaultChecklistPath returns the repository checklist path.
func DefaultChecklistPath(repositoryRoot string) string {
	return filepath.Join(repositoryRoot, "packaging", "evidence", "checklist-v1.json")
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("trailing JSON values")
	}
	return nil
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
