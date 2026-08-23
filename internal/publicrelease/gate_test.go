package publicrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/adoptionresult"
	"warptweet.com/warptweet/internal/releaseevidence"
)

func TestRepositoryGateKeepsHomebrewCTADark(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	gate, err := LoadGate(DefaultGatePath(root))
	if err != nil {
		t.Fatalf("LoadGate: %v", err)
	}
	if gate.HomebrewCTAEnabled {
		t.Fatal("homebrew CTA must remain dark until complete package evidence exists")
	}
	if gate.HomebrewCommand != DefaultHomebrewCommand ||
		gate.NextCommand != DefaultNextCommand ||
		gate.QualificationMessage != QualificationMessage {
		t.Fatalf("unexpected gate constants: %+v", gate)
	}
	if gate.Links["evidence_checklist"] != "packaging/evidence/checklist-v2.json" {
		t.Fatalf("evidence checklist = %q", gate.Links["evidence_checklist"])
	}
	if err := ValidateEnabledCTA(root, gate); err != nil {
		t.Fatalf("ValidateEnabledCTA dark gate: %v", err)
	}
	if err := VerifyRepository(root); err != nil {
		t.Fatalf("VerifyRepository: %v", err)
	}
}

func TestVerifyRepositoryRejectsMissingGate(t *testing.T) {
	t.Parallel()

	if err := VerifyRepository(t.TempDir()); err == nil {
		t.Fatal("accepted a tree without a public-release gate")
	}
}

func TestEnabledCTARequiresCompleteV2Evidence(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklistV2(releaseevidence.DefaultChecklistV2Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV2: %v", err)
	}

	missing := Gate{
		Kind:                     Kind,
		SchemaVersion:            SchemaVersion,
		HomebrewCTAEnabled:       true,
		HomebrewCommand:          DefaultHomebrewCommand,
		NextCommand:              DefaultNextCommand,
		QualificationMessage:     QualificationMessage,
		RequiredEvidenceDocument: "packaging/evidence/does-not-exist.json",
		Links:                    map[string]string{"evidence_checklist": "packaging/evidence/checklist-v2.json"},
	}
	if err := ValidateEnabledCTA(root, missing); err == nil {
		t.Fatal("enabled CTA accepted missing evidence document")
	}

	report := completeV2Report(checklist)
	report.ClientPackagePath = "dist/client.pkg"
	report.ServerPackagePath = "dist/server.deb"
	pseudoRoot, evidenceRel := writeV2EvidenceTree(t, root, report)
	if err := os.MkdirAll(filepath.Join(pseudoRoot, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pseudoRoot, report.ClientPackagePath), []byte("client"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pseudoRoot, report.ServerPackagePath), []byte("server"), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSum, err := sha256File(filepath.Join(pseudoRoot, report.ClientPackagePath))
	if err != nil {
		t.Fatal(err)
	}
	serverSum, err := sha256File(filepath.Join(pseudoRoot, report.ServerPackagePath))
	if err != nil {
		t.Fatal(err)
	}
	report.ClientPackageSHA256 = clientSum
	report.ServerPackageSHA256 = serverSum
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pseudoRoot, evidenceRel), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	enabled := Gate{
		Kind:                     Kind,
		SchemaVersion:            SchemaVersion,
		HomebrewCTAEnabled:       true,
		HomebrewCommand:          DefaultHomebrewCommand,
		NextCommand:              DefaultNextCommand,
		QualificationMessage:     QualificationMessage,
		RequiredEvidenceDocument: evidenceRel,
		Links:                    map[string]string{"evidence_checklist": "packaging/evidence/checklist-v2.json"},
	}
	if err := ValidateEnabledCTA(pseudoRoot, enabled); err != nil {
		t.Fatalf("ValidateEnabledCTA complete v2 evidence: %v", err)
	}
}

func TestEnabledCTARejectsV1Evidence(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklistV2(releaseevidence.DefaultChecklistV2Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV2: %v", err)
	}
	results := make([]releaseevidence.Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	v1 := map[string]any{
		"kind":                          releaseevidence.Kind,
		"schema_version":                1,
		"release_version":               "1.0.0",
		"source_commit":                 strings.Repeat("a", 40),
		"client_package_sha256":         strings.Repeat("b", 64),
		"server_package_sha256":         strings.Repeat("c", 64),
		"client_artifact_profile_id":    "darwin-arm64",
		"server_artifact_profile_id":    "linux-amd64",
		"client_engine_manifest_sha256": strings.Repeat("d", 64),
		"server_engine_manifest_sha256": strings.Repeat("e", 64),
		"client_platform":               "darwin",
		"server_platform":               "linux",
		"client_architecture":           "arm64",
		"server_architecture":           "amd64",
		"test_identity":                 "ci",
		"commands":                      []string{"./scripts/test-package-interop.sh"},
		"started_at":                    "2026-08-12T20:00:00Z",
		"finished_at":                   "2026-08-12T21:00:00Z",
		"package_to_package":            true,
		"source_tree_substitution":      false,
		"results":                       results,
	}
	pseudoRoot, evidenceRel := writeJSONEvidenceTree(t, root, v1)
	enabled := Gate{
		Kind:                     Kind,
		SchemaVersion:            SchemaVersion,
		HomebrewCTAEnabled:       true,
		HomebrewCommand:          DefaultHomebrewCommand,
		NextCommand:              DefaultNextCommand,
		QualificationMessage:     QualificationMessage,
		RequiredEvidenceDocument: evidenceRel,
		Links:                    map[string]string{"evidence_checklist": "packaging/evidence/checklist-v2.json"},
	}
	if err := ValidateEnabledCTA(pseudoRoot, enabled); err == nil {
		t.Fatal("enabled CTA accepted complete v1 evidence")
	}
}

func TestLoadGateRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	valid, err := os.ReadFile(DefaultGatePath(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []struct {
		suffix string
	}{
		{suffix: "}"},
		{suffix: `{"ok":false}`},
	} {
		path := filepath.Join(t.TempDir(), "gate.json")
		if err := os.WriteFile(path, append(append([]byte(nil), valid...), name.suffix...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadGate(path); err == nil {
			t.Fatalf("LoadGate accepted trailing %q", name.suffix)
		}
	}
}

func completeV2Report(checklist releaseevidence.Checklist) releaseevidence.ReportV2 {
	return sampleReportV2(checklist)
}

func sampleReportV2(checklist releaseevidence.Checklist) releaseevidence.ReportV2 {
	results := make([]releaseevidence.Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	return releaseevidence.ReportV2{
		Kind:                       releaseevidence.Kind,
		SchemaVersion:              releaseevidence.SchemaVersionV2,
		ContractID:                 adoptionresult.ContractID,
		ContractChecklistSHA256:    checklist.FileSHA256,
		ReleaseVersion:             "0.1.0-rc.1",
		SourceCommit:               strings.Repeat("a", 40),
		CleanTreeProof:             "git-status-empty",
		ClientPackageSHA256:        strings.Repeat("b", 64),
		ServerPackageSHA256:        strings.Repeat("c", 64),
		ClientArtifactProfileID:    "darwin-arm64",
		ServerArtifactProfileID:    "linux-amd64",
		ClientEngineManifestSHA256: strings.Repeat("e", 64),
		ServerEngineManifestSHA256: strings.Repeat("f", 64),
		ClientPlatform:             "darwin",
		ServerPlatform:             "linux",
		ClientArchitecture:         "arm64",
		ServerArchitecture:         "amd64",
		HostTarget:                 "127.0.0.1:5432",
		AuthorizationPolicy:        "30d-default-365d-max",
		RouteCount:                 1,
		RestartPolicies:            []string{"unless-stopped"},
		TestIdentity:               "v2-harness",
		Commands:                   []string{"./scripts/test-package-interop.sh"},
		StartedAt:                  "2026-08-16T00:00:00Z",
		FinishedAt:                 "2026-08-16T00:01:00Z",
		PackageToPackage:           true,
		SourceTreeSubstitution:     false,
		Results:                    results,
	}
}

func writeV2EvidenceTree(t *testing.T, sourceRoot string, report releaseevidence.ReportV2) (string, string) {
	t.Helper()
	return writeJSONEvidenceTree(t, sourceRoot, report)
}

func writeJSONEvidenceTree(t *testing.T, sourceRoot string, report any) (string, string) {
	t.Helper()
	pseudoRoot := t.TempDir()
	evidenceRel := "packaging/evidence/sample-complete.json"
	checklistDir := filepath.Join(pseudoRoot, "packaging", "evidence")
	if err := os.MkdirAll(checklistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourceChecklist, err := os.ReadFile(releaseevidence.DefaultChecklistV2Path(sourceRoot))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checklistDir, "checklist-v2.json"), sourceChecklist, 0o644); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pseudoRoot, evidenceRel), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return pseudoRoot, evidenceRel
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
