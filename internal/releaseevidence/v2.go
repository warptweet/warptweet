package releaseevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/adoptionresult"
)

const (
	// SchemaVersionV2 is the finite-grant release-evidence schema.
	SchemaVersionV2 = 2
)

// ReportV2 is one package-to-package evidence artifact for the v2 checklist.
type ReportV2 struct {
	Kind                       string   `json:"kind"`
	SchemaVersion              int      `json:"schema_version"`
	ContractID                 string   `json:"contract_id"`
	ContractChecklistSHA256    string   `json:"contract_checklist_sha256"`
	ReleaseVersion             string   `json:"release_version"`
	SourceCommit               string   `json:"source_commit"`
	CleanTreeProof             string   `json:"clean_tree_proof"`
	ClientPackageSHA256        string   `json:"client_package_sha256"`
	ServerPackageSHA256        string   `json:"server_package_sha256"`
	ClientPackagePath          string   `json:"client_package_path,omitempty"`
	ServerPackagePath          string   `json:"server_package_path,omitempty"`
	ClientArtifactProfileID    string   `json:"client_artifact_profile_id"`
	ServerArtifactProfileID    string   `json:"server_artifact_profile_id"`
	ClientEngineManifestSHA256 string   `json:"client_engine_manifest_sha256"`
	ServerEngineManifestSHA256 string   `json:"server_engine_manifest_sha256"`
	ClientPlatform             string   `json:"client_platform"`
	ServerPlatform             string   `json:"server_platform"`
	ClientArchitecture         string   `json:"client_architecture"`
	ServerArchitecture         string   `json:"server_architecture"`
	HostTarget                 string   `json:"host_target"`
	AuthorizationPolicy        string   `json:"authorization_policy"`
	RouteCount                 int      `json:"route_count"`
	RestartPolicies            []string `json:"restart_policies"`
	TestIdentity               string   `json:"test_identity"`
	EvaluatorIdentity          string   `json:"evaluator_identity,omitempty"`
	Commands                   []string `json:"commands"`
	StartedAt                  string   `json:"started_at"`
	FinishedAt                 string   `json:"finished_at"`
	RedactedLogPath            string   `json:"redacted_log_path,omitempty"`
	PackageToPackage           bool     `json:"package_to_package"`
	SourceTreeSubstitution     bool     `json:"source_tree_substitution"`
	Results                    []Result `json:"results"`
}

// LoadChecklistV2 reads the v2 repository checklist document.
func LoadChecklistV2(path string) (Checklist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Checklist{}, err
	}
	var checklist Checklist
	if err := decodeStrict(raw, &checklist); err != nil {
		return Checklist{}, err
	}
	sum := sha256.Sum256(raw)
	checklist.FileSHA256 = hex.EncodeToString(sum[:])
	if checklist.Kind != ChecklistKind || checklist.SchemaVersion != SchemaVersionV2 {
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

// ValidateReportV2 checks one v2 evidence report against the v2 checklist.
func ValidateReportV2(checklist Checklist, report ReportV2) error {
	if report.Kind != Kind || report.SchemaVersion != SchemaVersionV2 {
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
		{"contract_id", report.ContractID},
		{"contract_checklist_sha256", report.ContractChecklistSHA256},
		{"release_version", report.ReleaseVersion},
		{"source_commit", report.SourceCommit},
		{"clean_tree_proof", report.CleanTreeProof},
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
		{"host_target", report.HostTarget},
		{"authorization_policy", report.AuthorizationPolicy},
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
	if report.ContractID != adoptionresult.ContractID {
		return fmt.Errorf("contract_id must be %q", adoptionresult.ContractID)
	}
	if len(report.ContractChecklistSHA256) != 64 || !isLowerHex(report.ContractChecklistSHA256) {
		return fmt.Errorf("contract_checklist_sha256 must be 64 lowercase hex characters")
	}
	if checklist.FileSHA256 != "" && report.ContractChecklistSHA256 != checklist.FileSHA256 {
		return fmt.Errorf("contract_checklist_sha256 must be the SHA-256 of the canonical checklist file")
	}
	if report.CleanTreeProof == "not_recorded" {
		return fmt.Errorf("clean_tree_proof must be recorded")
	}
	if report.RouteCount < 0 {
		return fmt.Errorf("route_count must be non-negative")
	}
	seenPolicies := map[string]struct{}{}
	for _, policy := range report.RestartPolicies {
		switch policy {
		case "unless-stopped", "manual":
		default:
			return fmt.Errorf("invalid restart policy %q", policy)
		}
		if _, exists := seenPolicies[policy]; exists {
			return fmt.Errorf("duplicate restart policy %q", policy)
		}
		seenPolicies[policy] = struct{}{}
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
	started, err := time.Parse(time.RFC3339Nano, report.StartedAt)
	if err != nil {
		return fmt.Errorf("started_at must be RFC3339: %v", err)
	}
	finished, err := time.Parse(time.RFC3339Nano, report.FinishedAt)
	if err != nil {
		return fmt.Errorf("finished_at must be RFC3339: %v", err)
	}
	if finished.Before(started) {
		return fmt.Errorf("finished_at precedes started_at")
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
		case "pass", "fail", "blocked", "not_run":
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

// CompleteV2 reports whether every v2 checklist case passed.
func CompleteV2(report ReportV2) bool {
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

// DefaultChecklistV2Path returns the repository v2 checklist path.
func DefaultChecklistV2Path(repositoryRoot string) string {
	return filepath.Join(repositoryRoot, "packaging", "evidence", "checklist-v2.json")
}
