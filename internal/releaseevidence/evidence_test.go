package releaseevidence

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadChecklistAndValidateCompleteReport(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := LoadChecklist(DefaultChecklistPath(root))
	if err != nil {
		t.Fatalf("LoadChecklist: %v", err)
	}
	if len(checklist.Positive) < 8 || len(checklist.Negative) < 8 {
		t.Fatalf("checklist too small: +%d -%d", len(checklist.Positive), len(checklist.Negative))
	}

	report := sampleReport(checklist)
	if err := ValidateReport(checklist, report); err != nil {
		t.Fatalf("ValidateReport: %v", err)
	}
	if !Complete(report) {
		t.Fatal("expected complete report")
	}
}

func TestValidateReportRejectsSourceTreeAndMissingCases(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklist(DefaultChecklistPath(repositoryRoot(t)))
	if err != nil {
		t.Fatalf("LoadChecklist: %v", err)
	}
	report := sampleReport(checklist)
	report.SourceTreeSubstitution = true
	if err := ValidateReport(checklist, report); err == nil {
		t.Fatal("accepted source-tree substitution")
	}
	report = sampleReport(checklist)
	report.PackageToPackage = false
	if err := ValidateReport(checklist, report); err == nil {
		t.Fatal("accepted non package-to-package evidence")
	}
	report = sampleReport(checklist)
	report.Results = report.Results[:len(report.Results)-1]
	if err := ValidateReport(checklist, report); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("error=%v", err)
	}
	report = sampleReport(checklist)
	report.Results[0].Status = "not_run"
	if err := ValidateReport(checklist, report); err != nil {
		t.Fatalf("not_run should validate: %v", err)
	}
	if Complete(report) {
		t.Fatal("not_run must not count as complete")
	}
}

func sampleReport(checklist Checklist) Report {
	now := time.Date(2026, 8, 12, 18, 0, 0, 0, time.UTC)
	results := make([]Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	return Report{
		Kind:                       Kind,
		SchemaVersion:              SchemaVersion,
		ReleaseVersion:             "1.0.0",
		SourceCommit:               strings.Repeat("a", 40),
		ClientPackageSHA256:        strings.Repeat("b", 64),
		ServerPackageSHA256:        strings.Repeat("c", 64),
		ClientArtifactProfileID:    "darwin-arm64",
		ServerArtifactProfileID:    "linux-amd64",
		ClientEngineManifestSHA256: strings.Repeat("d", 64),
		ServerEngineManifestSHA256: strings.Repeat("e", 64),
		ClientPlatform:             "darwin 15.0",
		ServerPlatform:             "ubuntu 24.04",
		ClientArchitecture:         "arm64",
		ServerArchitecture:         "amd64",
		TestIdentity:               "ci-package-interop",
		Commands:                   []string{"./scripts/test-package-interop.sh"},
		StartedAt:                  now.Format(time.RFC3339Nano),
		FinishedAt:                 now.Add(time.Hour).Format(time.RFC3339Nano),
		RedactedLogPath:            "evidence/redacted.log",
		PackageToPackage:           true,
		SourceTreeSubstitution:     false,
		Results:                    results,
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
