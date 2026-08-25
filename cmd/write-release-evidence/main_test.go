package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/adoptionresult"
	"warptweet.com/warptweet/internal/releaseevidence"
)

func TestRunValidatesBeforeWrite(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(root))
	if err != nil {
		t.Fatal(err)
	}
	report := validReport(t, checklist)
	dir := t.TempDir()
	inPath := filepath.Join(dir, "draft.json")
	outPath := filepath.Join(dir, "out.json")
	writeJSON(t, inPath, report)
	if err := run(root, "", inPath, outPath, false); err != nil {
		t.Fatalf("valid write: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal(err)
	}

	report.Results = append(report.Results, report.Results[0])
	dupIn := filepath.Join(dir, "dup.json")
	dupOut := filepath.Join(dir, "dup-out.json")
	writeJSON(t, dupIn, report)
	if err := run(root, "", dupIn, dupOut, false); err == nil {
		t.Fatal("accepted duplicate result ids")
	}
	if _, err := os.Stat(dupOut); !os.IsNotExist(err) {
		t.Fatal("invalid draft was written")
	}

	index := completeIndex(t, checklist)
	indexIn := filepath.Join(dir, "index.json")
	indexOut := filepath.Join(dir, "index-out.json")
	writeJSON(t, indexIn, index)
	if err := run(root, "", indexIn, indexOut, true); err != nil {
		t.Fatalf("valid index write: %v", err)
	}
	if _, err := os.Stat(indexOut); err != nil {
		t.Fatal(err)
	}

	index.Reports = index.Reports[:1]
	incompleteIn := filepath.Join(dir, "index-incomplete.json")
	incompleteOut := filepath.Join(dir, "index-incomplete-out.json")
	writeJSON(t, incompleteIn, index)
	if err := run(root, "", incompleteIn, incompleteOut, true); err == nil {
		t.Fatal("accepted incomplete index")
	}
	if _, err := os.Stat(incompleteOut); !os.IsNotExist(err) {
		t.Fatal("incomplete index was written")
	}
}

func validReport(t *testing.T, checklist releaseevidence.ChecklistV3) releaseevidence.ReportV3 {
	t.Helper()
	raw, err := json.Marshal(sampleFromChecklist(checklist))
	if err != nil {
		t.Fatal(err)
	}
	report, err := releaseevidence.DecodeReportV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func sampleFromChecklist(checklist releaseevidence.ChecklistV3) releaseevidence.ReportV3 {
	results := make([]releaseevidence.Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, releaseevidence.Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	return releaseevidence.ReportV3{
		Kind:                       releaseevidence.Kind,
		SchemaVersion:              releaseevidence.SchemaVersionV3,
		ContractID:                 adoptionresult.ContractID,
		ContractChecklistSHA256:    checklist.FileSHA256,
		ReleaseVersion:             "0.1.0-rc.1",
		SourceCommit:               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CleanTreeProof:             "git-status-empty",
		ClientPackageSHA256:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ServerPackageSHA256:        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ClientArtifactProfileID:    "darwin-arm64",
		ServerArtifactProfileID:    "linux-amd64",
		ClientEngineManifestSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		ServerEngineManifestSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		ClientPlatform:             "darwin",
		ServerPlatform:             "linux",
		ClientArchitecture:         "arm64",
		ServerArchitecture:         "amd64",
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
		CellClasses:                []string{releaseevidence.CellClassMatrix},
		Results:                    results,
		Networking: releaseevidence.NetworkingEvidence{
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
			InviteDials: releaseevidence.ServiceDialEvidence{
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
		},
	}
}

func completeIndex(t *testing.T, checklist releaseevidence.ChecklistV3) releaseevidence.IndexV3 {
	t.Helper()
	var reports []releaseevidence.ReportV3
	for _, cell := range releaseevidence.RequiredMatrixCells(checklist.Checklist()) {
		report := sampleFromChecklist(checklist)
		report.ClientArtifactProfileID = cell.Client
		report.ServerArtifactProfileID = cell.Server
		report.ClientArchitecture = architectureFromProfile(cell.Client)
		report.ServerArchitecture = architectureFromProfile(cell.Server)
		report.CellClasses = []string{releaseevidence.CellClassMatrix}
		reports = append(reports, report)
	}
	for _, cell := range releaseevidence.RequiredNetworkingCells(checklist) {
		reports = append(reports, networkingReportFromChecklist(checklist, cell))
	}
	return releaseevidence.IndexV3{
		Kind:                    releaseevidence.IndexKind,
		SchemaVersion:           releaseevidence.SchemaVersionV3,
		ContractID:              adoptionresult.ContractID,
		ContractChecklistSHA256: checklist.FileSHA256,
		Reports:                 reports,
	}
}

func networkingReportFromChecklist(checklist releaseevidence.ChecklistV3, cell releaseevidence.NetworkingCell) releaseevidence.ReportV3 {
	report := sampleFromChecklist(checklist)
	report.CellClasses = []string{releaseevidence.CellClassNetworking}
	if cell.ClientArtifactProfileID != "" {
		report.ClientArtifactProfileID = cell.ClientArtifactProfileID
		report.ClientArchitecture = architectureFromProfile(cell.ClientArtifactProfileID)
	}
	if cell.ServerArtifactProfileID != "" {
		report.ServerArtifactProfileID = cell.ServerArtifactProfileID
		report.ServerArchitecture = architectureFromProfile(cell.ServerArtifactProfileID)
	}
	net := report.Networking
	net.CellID = cell.ID
	net.PublicationModel = cell.PublicationModel
	switch cell.PublicationModel {
	case "one_to_one_nat", "passthrough_nlb":
		net.Binds.Data.Address = "10.168.0.2"
		net.Binds.Enrollment.Address = "10.168.0.2"
		net.Dials.Data.Host = "34.20.174.226"
		net.Dials.Enrollment.Host = "34.20.174.226"
		net.ObservedListeners.Data = "10.168.0.2:2222"
		net.ObservedListeners.Enrollment = "10.168.0.2:29722"
		net.ClientDials[0].Host = "34.20.174.226"
		net.ClientDials[1].Host = "34.20.174.226"
		net.DataResolvedAddr = "34.20.174.226"
		net.EnrollmentResolvedAddr = "34.20.174.226"
	case "port_mapped":
		net.Dials.Data.Port = 443
		net.Dials.Enrollment.Host = "enroll.example.com"
		net.Dials.Enrollment.Port = 443
		net.ClientDials[0].Port = 443
		net.ClientDials[1].Host = "enroll.example.com"
		net.ClientDials[1].Port = 443
	case "dns_dial":
		net.Dials.Data.Host = "tunnel.example.com"
		net.Dials.Enrollment.Host = "enroll.example.com"
		net.ClientDials[0].Host = "tunnel.example.com"
		net.ClientDials[1].Host = "enroll.example.com"
		net.DataResolvedAddr = "34.20.174.226"
		net.EnrollmentResolvedAddr = "34.20.174.227"
	case "ipv6_bind_equals_dial":
		net.Binds.Data.Address = "2001:db8::2"
		net.Binds.Enrollment.Address = "2001:db8::2"
		net.Dials.Data.Host = "2001:db8::2"
		net.Dials.Enrollment.Host = "2001:db8::2"
		net.ObservedListeners.Data = "[2001:db8::2]:2222"
		net.ObservedListeners.Enrollment = "[2001:db8::2]:29722"
		net.ClientDials[0].Host = "2001:db8::2"
		net.ClientDials[1].Host = "2001:db8::2"
		net.DataResolvedAddr = "2001:db8::2"
		net.EnrollmentResolvedAddr = "2001:db8::2"
	}
	net.InviteDials = net.Dials
	net.InviteDialsMatchPublished = true
	report.Networking = net
	return report
}

func architectureFromProfile(profile string) string {
	if strings.Contains(profile, "amd64") {
		return "amd64"
	}
	return "arm64"
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
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
