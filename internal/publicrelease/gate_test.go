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
	if gate.Links["evidence_checklist"] != "packaging/evidence/checklist-v3.json" {
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

func TestEnabledCTARequiresCompleteV3Index(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV3: %v", err)
	}

	missing := Gate{
		Kind:                     Kind,
		SchemaVersion:            SchemaVersion,
		HomebrewCTAEnabled:       true,
		HomebrewCommand:          DefaultHomebrewCommand,
		NextCommand:              DefaultNextCommand,
		QualificationMessage:     QualificationMessage,
		RequiredEvidenceDocument: "packaging/evidence/does-not-exist.json",
		Links:                    map[string]string{"evidence_checklist": "packaging/evidence/checklist-v3.json"},
	}
	if err := ValidateEnabledCTA(root, missing); err == nil {
		t.Fatal("enabled CTA accepted missing evidence document")
	}

	reports := completeV3IndexReports(checklist)
	reports[0].ClientPackagePath = "dist/client.pkg"
	reports[0].ServerPackagePath = "dist/server.deb"
	pseudoRoot, evidenceRel := writeV3IndexTree(t, root, reports)
	if err := os.MkdirAll(filepath.Join(pseudoRoot, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pseudoRoot, reports[0].ClientPackagePath), []byte("client"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pseudoRoot, reports[0].ServerPackagePath), []byte("server"), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSum, err := sha256File(filepath.Join(pseudoRoot, reports[0].ClientPackagePath))
	if err != nil {
		t.Fatal(err)
	}
	serverSum, err := sha256File(filepath.Join(pseudoRoot, reports[0].ServerPackagePath))
	if err != nil {
		t.Fatal(err)
	}
	reports[0].ClientPackageSHA256 = clientSum
	reports[0].ServerPackageSHA256 = serverSum
	writeV3IndexFile(t, filepath.Join(pseudoRoot, evidenceRel), checklist, reports)
	enabled := Gate{
		Kind:                     Kind,
		SchemaVersion:            SchemaVersion,
		HomebrewCTAEnabled:       true,
		HomebrewCommand:          DefaultHomebrewCommand,
		NextCommand:              DefaultNextCommand,
		QualificationMessage:     QualificationMessage,
		RequiredEvidenceDocument: evidenceRel,
		Links:                    map[string]string{"evidence_checklist": "packaging/evidence/checklist-v3.json"},
	}
	if err := ValidateEnabledCTA(pseudoRoot, enabled); err != nil {
		t.Fatalf("ValidateEnabledCTA complete v3 index: %v", err)
	}
}

func TestEnabledCTARejectsV1Evidence(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV3: %v", err)
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
		Links:                    map[string]string{"evidence_checklist": "packaging/evidence/checklist-v3.json"},
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

func completeV3IndexReports(checklist releaseevidence.ChecklistV3) []releaseevidence.ReportV3 {
	var reports []releaseevidence.ReportV3
	for _, cell := range releaseevidence.RequiredMatrixCells(checklist.Checklist()) {
		reports = append(reports, sampleV3Report(checklist, cell.Client, cell.Server, []string{releaseevidence.CellClassMatrix}, ""))
	}
	for _, cell := range releaseevidence.RequiredNetworkingCells(checklist) {
		report := sampleV3Report(checklist, "darwin-arm64", "linux-arm64", []string{releaseevidence.CellClassNetworking}, cell.ID)
		if cell.ClientArtifactProfileID != "" {
			report.ClientArtifactProfileID = cell.ClientArtifactProfileID
		}
		if cell.ServerArtifactProfileID != "" {
			report.ServerArtifactProfileID = cell.ServerArtifactProfileID
		}
		report.Networking.CellID = cell.ID
		report.Networking.PublicationModel = cell.PublicationModel
		switch cell.PublicationModel {
		case "one_to_one_nat", "passthrough_nlb":
			report.Networking.Binds.Data.Address = "10.168.0.2"
			report.Networking.Binds.Enrollment.Address = "10.168.0.2"
			report.Networking.Dials.Data.Host = "34.20.174.226"
			report.Networking.Dials.Enrollment.Host = "34.20.174.226"
			report.Networking.ObservedListeners.Data = "10.168.0.2:2222"
			report.Networking.ObservedListeners.Enrollment = "10.168.0.2:29722"
			report.Networking.ClientDials[0].Host = "34.20.174.226"
			report.Networking.ClientDials[1].Host = "34.20.174.226"
			report.Networking.DataResolvedAddr = "34.20.174.226"
			report.Networking.EnrollmentResolvedAddr = "34.20.174.226"
		case "dns_dial":
			report.Networking.Dials.Data.Host = "tunnel.example.com"
			report.Networking.Dials.Enrollment.Host = "enroll.example.com"
			report.Networking.ClientDials[0].Host = "tunnel.example.com"
			report.Networking.ClientDials[1].Host = "enroll.example.com"
		case "ipv6_bind_equals_dial":
			report.Networking.Binds.Data.Address = "2001:db8::2"
			report.Networking.Binds.Enrollment.Address = "2001:db8::2"
			report.Networking.Dials.Data.Host = "2001:db8::2"
			report.Networking.Dials.Enrollment.Host = "2001:db8::2"
			report.Networking.ObservedListeners.Data = "[2001:db8::2]:2222"
			report.Networking.ObservedListeners.Enrollment = "[2001:db8::2]:29722"
			report.Networking.ClientDials[0].Host = "2001:db8::2"
			report.Networking.ClientDials[1].Host = "2001:db8::2"
			report.Networking.DataResolvedAddr = "2001:db8::2"
			report.Networking.EnrollmentResolvedAddr = "2001:db8::2"
		case "port_mapped":
			report.Networking.Dials.Data.Port = 443
			report.Networking.Dials.Enrollment.Host = "enroll.example.com"
			report.Networking.Dials.Enrollment.Port = 443
			report.Networking.ClientDials[0].Port = 443
			report.Networking.ClientDials[1].Host = "enroll.example.com"
			report.Networking.ClientDials[1].Port = 443
		}
		reports = append(reports, report)
	}
	return reports
}

func sampleV3Report(checklist releaseevidence.ChecklistV3, client, server string, classes []string, cellID string) releaseevidence.ReportV3 {
	results := make([]releaseevidence.Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	clientArch := "arm64"
	serverArch := "amd64"
	if strings.Contains(client, "amd64") {
		clientArch = "amd64"
	}
	if strings.Contains(server, "arm64") {
		serverArch = "arm64"
	}
	return releaseevidence.ReportV3{
		Kind:                       releaseevidence.Kind,
		SchemaVersion:              releaseevidence.SchemaVersionV3,
		ContractID:                 adoptionresult.ContractID,
		ContractChecklistSHA256:    checklist.FileSHA256,
		ReleaseVersion:             "0.1.0-rc.1",
		SourceCommit:               strings.Repeat("a", 40),
		CleanTreeProof:             "git-status-empty",
		ClientPackageSHA256:        strings.Repeat("b", 64),
		ServerPackageSHA256:        strings.Repeat("c", 64),
		ClientArtifactProfileID:    client,
		ServerArtifactProfileID:    server,
		ClientEngineManifestSHA256: strings.Repeat("e", 64),
		ServerEngineManifestSHA256: strings.Repeat("f", 64),
		ClientPlatform:             "darwin",
		ServerPlatform:             "linux",
		ClientArchitecture:         clientArch,
		ServerArchitecture:         serverArch,
		HostTarget:                 "127.0.0.1:5432",
		AuthorizationPolicy:        "30d-default-365d-max",
		RouteCount:                 1,
		RestartPolicies:            []string{"unless-stopped"},
		TestIdentity:               "v3-harness",
		Commands:                   []string{"./scripts/interop/orchestrate.sh"},
		StartedAt:                  "2026-08-24T00:00:00Z",
		FinishedAt:                 "2026-08-24T00:01:00Z",
		PackageToPackage:           true,
		SourceTreeSubstitution:     false,
		CellClasses:                classes,
		Results:                    results,
		Networking:                 sampleDirectNetworking(cellID),
	}
}

func sampleDirectNetworking(cellID string) releaseevidence.NetworkingEvidence {
	return releaseevidence.NetworkingEvidence{
		CellID:                      cellID,
		PublicationModel:            "direct",
		PublishedEndpointGeneration: 1,
		InviteSchemaVersion:         3,
		InviteDialsMatchPublished:   true,
		Binds: releaseevidence.ServiceBindEvidence{
			Data:       releaseevidence.BindEvidence{Address: "203.0.113.10", Port: 2222},
			Enrollment: releaseevidence.BindEvidence{Address: "203.0.113.10", Port: 29722},
		},
		Dials: releaseevidence.ServiceDialEvidence{
			Data:       releaseevidence.DialEvidence{Host: "203.0.113.10", Port: 2222},
			Enrollment: releaseevidence.DialEvidence{Host: "203.0.113.10", Port: 29722},
		},
		ObservedListeners: releaseevidence.ObservedListenersEvidence{
			Data:       "203.0.113.10:2222",
			Enrollment: "203.0.113.10:29722",
			MatchBinds: true,
		},
		TestDNATAbsent:      true,
		LoopbackAliasAbsent: true,
		ClientDials: []releaseevidence.ClientDialEvidence{
			{Leg: "data", Host: "203.0.113.10", Port: 2222, Status: "pass"},
			{Leg: "enrollment", Host: "203.0.113.10", Port: 29722, Status: "pass"},
		},
		SPKIResult:                      releaseevidence.CheckEvidence{Status: "pass"},
		HostKeyResult:                   releaseevidence.CheckEvidence{Status: "pass"},
		EnrollmentResolvedAddr:          "203.0.113.10",
		DataResolvedAddr:                "203.0.113.10",
		OperatorFirewallAssumptions:     "host firewall allows 2222/tcp and 29722/tcp",
		OperatorLoadBalancerAssumptions: "none; public address on the guest NIC",
		PackageOnly:                     true,
		CleanTree:                       true,
	}
}

func writeV3IndexTree(t *testing.T, sourceRoot string, reports []releaseevidence.ReportV3) (string, string) {
	t.Helper()
	pseudoRoot := t.TempDir()
	evidenceRel := "packaging/evidence/sample-complete-index.json"
	checklistDir := filepath.Join(pseudoRoot, "packaging", "evidence")
	if err := os.MkdirAll(checklistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourceChecklist, err := os.ReadFile(releaseevidence.DefaultChecklistV3Path(sourceRoot))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checklistDir, "checklist-v3.json"), sourceChecklist, 0o644); err != nil {
		t.Fatal(err)
	}
	checklist, err := releaseevidence.LoadChecklistV3(filepath.Join(checklistDir, "checklist-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeV3IndexFile(t, filepath.Join(pseudoRoot, evidenceRel), checklist, reports)
	return pseudoRoot, evidenceRel
}

func writeV3IndexFile(t *testing.T, path string, checklist releaseevidence.ChecklistV3, reports []releaseevidence.ReportV3) {
	t.Helper()
	index := releaseevidence.IndexV3{
		Kind:                    releaseevidence.IndexKind,
		SchemaVersion:           releaseevidence.SchemaVersionV3,
		ContractID:              adoptionresult.ContractID,
		ContractChecklistSHA256: checklist.FileSHA256,
		Reports:                 reports,
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeJSONEvidenceTree(t *testing.T, sourceRoot string, report any) (string, string) {
	t.Helper()
	pseudoRoot := t.TempDir()
	evidenceRel := "packaging/evidence/sample-complete.json"
	checklistDir := filepath.Join(pseudoRoot, "packaging", "evidence")
	if err := os.MkdirAll(checklistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourceChecklist, err := os.ReadFile(releaseevidence.DefaultChecklistV3Path(sourceRoot))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checklistDir, "checklist-v3.json"), sourceChecklist, 0o644); err != nil {
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
