package publicrelease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	if err := ValidateEnabledCTA(root, gate); err != nil {
		t.Fatalf("ValidateEnabledCTA dark gate: %v", err)
	}
}

func TestEnabledCTARequiresCompleteEvidence(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklist(releaseevidence.DefaultChecklistPath(root))
	if err != nil {
		t.Fatalf("LoadChecklist: %v", err)
	}

	missing := Gate{
		Kind:                     Kind,
		SchemaVersion:            SchemaVersion,
		HomebrewCTAEnabled:       true,
		HomebrewCommand:          DefaultHomebrewCommand,
		NextCommand:              DefaultNextCommand,
		QualificationMessage:     QualificationMessage,
		RequiredEvidenceDocument: "packaging/evidence/does-not-exist.json",
	}
	if err := ValidateEnabledCTA(root, missing); err == nil {
		t.Fatal("enabled CTA accepted missing evidence document")
	}

	results := make([]releaseevidence.Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	now := time.Date(2026, 8, 12, 20, 0, 0, 0, time.UTC)
	report := releaseevidence.Report{
		Kind:                       releaseevidence.Kind,
		SchemaVersion:              releaseevidence.SchemaVersion,
		ReleaseVersion:             "1.0.0",
		SourceCommit:               strings.Repeat("a", 40),
		ClientPackageSHA256:        strings.Repeat("b", 64),
		ServerPackageSHA256:        strings.Repeat("c", 64),
		ClientArtifactProfileID:    "darwin-arm64",
		ServerArtifactProfileID:    "linux-amd64",
		ClientEngineManifestSHA256: strings.Repeat("d", 64),
		ServerEngineManifestSHA256: strings.Repeat("e", 64),
		ClientPlatform:             "darwin",
		ServerPlatform:             "linux",
		ClientArchitecture:         "arm64",
		ServerArchitecture:         "amd64",
		TestIdentity:               "ci",
		Commands:                   []string{"./scripts/test-package-interop.sh"},
		StartedAt:                  now.Format(time.RFC3339Nano),
		FinishedAt:                 now.Add(time.Hour).Format(time.RFC3339Nano),
		PackageToPackage:           true,
		SourceTreeSubstitution:     false,
		Results:                    results,
	}

	pseudoRoot := t.TempDir()
	evidenceRel := "packaging/evidence/sample-complete.json"
	checklistDir := filepath.Join(pseudoRoot, "packaging", "evidence")
	if err := os.MkdirAll(checklistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourceChecklist, err := os.ReadFile(releaseevidence.DefaultChecklistPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checklistDir, "checklist-v1.json"), sourceChecklist, 0o644); err != nil {
		t.Fatal(err)
	}
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
	}
	if err := ValidateEnabledCTA(pseudoRoot, enabled); err != nil {
		t.Fatalf("ValidateEnabledCTA complete evidence: %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
