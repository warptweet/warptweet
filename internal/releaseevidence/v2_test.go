package releaseevidence

import (
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/adoptionresult"
)

func TestLoadChecklistV2AndRejectIncomplete(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := LoadChecklistV2(DefaultChecklistV2Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV2: %v", err)
	}
	if checklist.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("schema=%d", checklist.SchemaVersion)
	}
	report := sampleReportV2(checklist)
	if err := ValidateReportV2(checklist, report); err != nil {
		t.Fatalf("ValidateReportV2: %v", err)
	}
	if !CompleteV2(report) {
		t.Fatal("expected complete v2 report")
	}
	report.Results[0].Status = "not_run"
	if err := ValidateReportV2(checklist, report); err != nil {
		t.Fatalf("not_run should validate: %v", err)
	}
	if CompleteV2(report) {
		t.Fatal("not_run must not complete v2 evidence")
	}
	report = sampleReportV2(checklist)
	report.Results[0].Status = "blocked"
	if err := ValidateReportV2(checklist, report); err != nil {
		t.Fatalf("blocked should validate: %v", err)
	}
	if CompleteV2(report) {
		t.Fatal("blocked must not complete v2 evidence")
	}
	report = sampleReportV2(checklist)
	report.ContractChecklistSHA256 = strings.Repeat("d", 64)
	if err := ValidateReportV2(checklist, report); err == nil {
		t.Fatal("accepted arbitrary contract checklist digest")
	}
}

func TestValidateReportV2Rejections(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV2(DefaultChecklistV2Path(repositoryRoot(t)))
	if err != nil {
		t.Fatalf("LoadChecklistV2: %v", err)
	}
	for name, mutate := range map[string]func(*ReportV2){
		"not package to package":   func(r *ReportV2) { r.PackageToPackage = false },
		"source substitution":      func(r *ReportV2) { r.SourceTreeSubstitution = true },
		"missing host target":      func(r *ReportV2) { r.HostTarget = "" },
		"short source commit":      func(r *ReportV2) { r.SourceCommit = "abc" },
		"unknown result id":        func(r *ReportV2) { r.Results[0].ID = "not-a-case" },
		"class mismatch":           func(r *ReportV2) { r.Results[0].Class = "negative" },
		"missing result":           func(r *ReportV2) { r.Results = r.Results[1:] },
		"no commands":              func(r *ReportV2) { r.Commands = nil },
		"invalid restart policy":   func(r *ReportV2) { r.RestartPolicies = []string{"always"} },
		"duplicate restart policy": func(r *ReportV2) { r.RestartPolicies = []string{"unless-stopped", "unless-stopped"} },
		"malformed started_at":     func(r *ReportV2) { r.StartedAt = "not-a-timestamp" },
		"finished before started":  func(r *ReportV2) { r.FinishedAt = "2026-08-15T00:00:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := sampleReportV2(checklist)
			mutate(&report)
			if err := ValidateReportV2(checklist, report); err == nil {
				t.Fatalf("accepted invalid report: %s", name)
			}
		})
	}
}

func sampleReportV2(checklist Checklist) ReportV2 {
	results := make([]Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	return ReportV2{
		Kind:                       Kind,
		SchemaVersion:              SchemaVersionV2,
		ContractID:                 adoptionresult.ContractID,
		ContractChecklistSHA256:    adoptionresult.ContractChecklistSHA256,
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
