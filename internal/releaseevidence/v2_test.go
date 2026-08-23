package releaseevidence

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestChecklistSHA256BindsCanonicalFile(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	path := DefaultChecklistV2Path(root)
	checklist, err := LoadChecklistV2(path)
	if err != nil {
		t.Fatal(err)
	}
	if checklist.FileSHA256 != "87c98bcaa7cb34a7955157b5c2fba7d3e5b824866bb84f843ee9a50e7c1534ad" {
		t.Fatalf("FileSHA256=%s", checklist.FileSHA256)
	}
	report := sampleReportV2(checklist)
	if err := ValidateReportV2(checklist, report); err != nil {
		t.Fatal(err)
	}
	mutated := checklist
	mutated.FileSHA256 = strings.Repeat("0", 64)
	if err := ValidateReportV2(mutated, report); err == nil {
		t.Fatal("accepted report after checklist digest changed")
	}
}

func TestValidateIndexRequiresEveryMatrixCell(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV2(DefaultChecklistV2Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	cells := RequiredMatrixCells(checklist)
	if len(cells) != 4 {
		t.Fatalf("cells=%d, want 4", len(cells))
	}
	var reports []ReportV2
	for _, cell := range cells {
		report := sampleReportV2(checklist)
		report.ClientArtifactProfileID = cell.Client
		report.ServerArtifactProfileID = cell.Server
		reports = append(reports, report)
	}
	if err := ValidateIndex(checklist, reports); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIndex(checklist, reports[:1]); err == nil {
		t.Fatal("accepted incomplete matrix")
	}
	dup := append([]ReportV2{}, reports...)
	dup[1] = reports[0]
	if err := ValidateIndex(checklist, dup); err == nil {
		t.Fatal("accepted duplicate cell")
	}
	extra := append([]ReportV2{}, reports...)
	unknown := sampleReportV2(checklist)
	unknown.ClientArtifactProfileID = "windows-amd64"
	unknown.ServerArtifactProfileID = "linux-amd64"
	if err := ValidateIndex(checklist, append(extra, unknown)); err == nil {
		t.Fatal("accepted unknown matrix cell")
	}
	reports[0].Results[0].Status = "not_run"
	if CompleteIndex(reports) {
		t.Fatal("not_run completed the index")
	}
}

func TestBindArtifactDigestsRejectsFakeAndMissing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	client := filepath.Join("client.pkg")
	server := filepath.Join("server.deb")
	if err := os.WriteFile(filepath.Join(root, client), []byte("client-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, server), []byte("server-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSum, err := fileSHA256(filepath.Join(root, client))
	if err != nil {
		t.Fatal(err)
	}
	serverSum, err := fileSHA256(filepath.Join(root, server))
	if err != nil {
		t.Fatal(err)
	}
	report := ReportV2{
		ClientPackagePath:   client,
		ServerPackagePath:   server,
		ClientPackageSHA256: clientSum,
		ServerPackageSHA256: serverSum,
	}
	if err := BindArtifactDigests(root, report); err != nil {
		t.Fatal(err)
	}
	report.ClientPackageSHA256 = strings.Repeat("0", 64)
	if err := BindArtifactDigests(root, report); err == nil {
		t.Fatal("accepted fake client digest")
	}
	report.ClientPackageSHA256 = clientSum
	report.ServerPackagePath = "missing.deb"
	if err := BindArtifactDigests(root, report); err == nil {
		t.Fatal("accepted missing server artifact")
	}
	report.ServerPackagePath = ""
	if err := BindArtifactDigests(root, report); err == nil {
		t.Fatal("accepted missing package path")
	}
	if err := BindArtifactDigests(root, ReportV2{
		ClientPackagePath:   "../client.pkg",
		ServerPackagePath:   server,
		ClientPackageSHA256: clientSum,
		ServerPackageSHA256: serverSum,
	}); err == nil {
		t.Fatal("accepted path escape")
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
