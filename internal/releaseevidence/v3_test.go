package releaseevidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/adoptionresult"
	"warptweet.com/warptweet/internal/locator"
)

func TestLoadChecklistV3AndRejectIncomplete(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV3: %v", err)
	}
	if checklist.SchemaVersion != SchemaVersionV3 {
		t.Fatalf("schema=%d", checklist.SchemaVersion)
	}
	if checklist.FileSHA256 != "ca811ef2ffa43e3b96282aedb396b83c583d9e0c00dd4bd9c87a0037a4999b4d" {
		t.Fatalf("FileSHA256=%s", checklist.FileSHA256)
	}
	cells := RequiredMatrixCells(checklist.Checklist())
	if len(cells) != 4 {
		t.Fatalf("matrix cells=%d, want 4", len(cells))
	}
	requiredNet := RequiredNetworkingCells(checklist)
	if len(requiredNet) != 4 {
		t.Fatalf("required networking cells=%d, want 4", len(requiredNet))
	}
	report := sampleReportV3(checklist)
	if err := ValidateReportV3(checklist, report); err != nil {
		t.Fatalf("ValidateReportV3: %v", err)
	}
	if !CompleteV3(report) {
		t.Fatal("expected complete v3 report")
	}
	report.Results[0].Status = "not_run"
	if err := ValidateReportV3(checklist, report); err != nil {
		t.Fatalf("not_run should validate: %v", err)
	}
	if CompleteV3(report) {
		t.Fatal("not_run must not complete v3 evidence")
	}
}

func TestValidateReportV3Rejections(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatalf("LoadChecklistV3: %v", err)
	}
	for name, mutate := range map[string]func(*ReportV3){
		"v2 schema version":        func(r *ReportV3) { r.SchemaVersion = SchemaVersionV2 },
		"not package to package":   func(r *ReportV3) { r.PackageToPackage = false },
		"source substitution":      func(r *ReportV3) { r.SourceTreeSubstitution = true },
		"missing host target":      func(r *ReportV3) { r.HostTarget = "" },
		"short source commit":      func(r *ReportV3) { r.SourceCommit = "abc" },
		"unknown result id":        func(r *ReportV3) { r.Results[0].ID = "not-a-case" },
		"class mismatch":           func(r *ReportV3) { r.Results[0].Class = "negative" },
		"missing result":           func(r *ReportV3) { r.Results = r.Results[1:] },
		"duplicate result id":      func(r *ReportV3) { r.Results = append(r.Results, r.Results[0]) },
		"no commands":              func(r *ReportV3) { r.Commands = nil },
		"empty restart policies":   func(r *ReportV3) { r.RestartPolicies = nil },
		"invalid restart policy":   func(r *ReportV3) { r.RestartPolicies = []string{"always"} },
		"proxy load balancer":      func(r *ReportV3) { r.Networking.PublicationModel = publicationProxyLB },
		"unspecified bind":         func(r *ReportV3) { r.Networking.Binds.Data.Address = "0.0.0.0" },
		"empty cell classes":       func(r *ReportV3) { r.CellClasses = nil },
		"wrong checklist digest":   func(r *ReportV3) { r.ContractChecklistSHA256 = strings.Repeat("d", 64) },
		"missing client dials":     func(r *ReportV3) { r.Networking.ClientDials = r.Networking.ClientDials[:1] },
		"client dial bind address": func(r *ReportV3) { r.Networking.ClientDials[0].Host = "192.0.2.55" },
		"unspecified observed match": func(r *ReportV3) {
			r.Networking.ObservedListeners.Data = "0.0.0.0:2222"
			r.Networking.ObservedListeners.MatchBinds = true
		},
		"match_binds false when equal": func(r *ReportV3) { r.Networking.ObservedListeners.MatchBinds = false },
		"invite mismatch flag": func(r *ReportV3) {
			r.Networking.InviteDials.Data.Host = "192.0.2.9"
			r.Networking.InviteDialsMatchPublished = true
		},
		"dirty tree claimed clean": func(r *ReportV3) {
			r.CleanTreeProof = "dirty-abcd"
			r.Networking.CleanTree = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := sampleReportV3(checklist)
			mutate(&report)
			if err := ValidateReportV3(checklist, report); err == nil {
				t.Fatalf("accepted invalid report: %s", name)
			}
		})
	}
}

func TestWriteReportV3ValidatesBeforeWrite(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.json")
	report := sampleReportV3(checklist)
	if err := WriteReportV3(validPath, checklist, report); err != nil {
		t.Fatalf("WriteReportV3 valid: %v", err)
	}
	raw, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReportV3(raw)
	if err != nil {
		t.Fatalf("DecodeReportV3: %v", err)
	}
	if err := ValidateReportV3(checklist, decoded); err != nil {
		t.Fatalf("round-trip: %v", err)
	}

	dup := sampleReportV3(checklist)
	dup.Results = append(dup.Results, dup.Results[0])
	dupPath := filepath.Join(dir, "duplicate.json")
	if err := WriteReportV3(dupPath, checklist, dup); err == nil {
		t.Fatal("WriteReportV3 accepted duplicate result ids")
	} else if !strings.Contains(err.Error(), "duplicate result id") {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := os.Lstat(dupPath); !os.IsNotExist(err) {
		t.Fatal("invalid report was written")
	}

	if err := WriteReportV3(validPath, checklist, report); err == nil {
		t.Fatal("WriteReportV3 overwrote an existing file")
	}
}

func TestDecodeReportV3RejectsAdditionalProperties(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	report := sampleReportV3(checklist)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected_field"] = true
	injected, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReportV3(injected); err == nil {
		t.Fatal("accepted additional top-level property")
	}
	networking := object["networking"].(map[string]any)
	delete(object, "unexpected_field")
	networking["dnat_helper"] = "wt-gcp-bind"
	injected, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReportV3(injected); err == nil {
		t.Fatal("accepted additional networking property")
	}
}

func TestV2ReportRejectsNetworkingFields(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV2(DefaultChecklistV2Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	report := sampleReportV2(checklist)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["networking"] = map[string]any{"publication_model": "one_to_one_nat"}
	injected, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReportV2
	if err := decodeStrict(injected, &decoded); err == nil {
		t.Fatal("v2 decoder accepted networking fields")
	}
	schema := string(readRepoFile(t, filepath.Join(repositoryRoot(t), "schemas", "release-evidence-v2.schema.json")))
	if !strings.Contains(schema, `"additionalProperties": false`) {
		t.Fatal("v2 schema must keep additionalProperties false")
	}
	for _, forbidden := range []string{
		`"cell_classes"`,
		`"publication_model"`,
		`"test_dnat_absent"`,
		`"enrollment_resolved_addr"`,
		`"data_resolved_addr"`,
	} {
		if strings.Contains(schema, forbidden) {
			t.Errorf("v2 schema grew %s", forbidden)
		}
	}
}

func TestValidateIndexV3RequiresMatrixAndNetworkingCells(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	reports := completeIndexReportsV3(checklist)
	if err := ValidateIndexV3(checklist, reports); err != nil {
		t.Fatalf("ValidateIndexV3: %v", err)
	}
	if !CompleteIndexV3(checklist, reports) {
		t.Fatal("expected complete v3 index")
	}
	if err := ValidateIndexV3(checklist, reports[:4]); err == nil {
		t.Fatal("accepted matrix without required networking cells")
	}
	dup := append([]ReportV3{}, reports...)
	dup[1] = reports[0]
	if err := ValidateIndexV3(checklist, dup); err == nil {
		t.Fatal("accepted duplicate matrix cell")
	}
	gceOnly := sampleNetworkingReportV3(checklist, "gce-one-to-one-nat")
	if err := ValidateIndexV3(checklist, []ReportV3{gceOnly}); err == nil {
		t.Fatal("accepted a single GCE cell as the public matrix")
	}
	reports[0].Results[0].Status = "not_run"
	if CompleteIndexV3(checklist, reports) {
		t.Fatal("not_run completed the v3 index")
	}
	err = IndexCompletenessError(checklist, reports)
	if err == nil {
		t.Fatal("expected incomplete index error")
	}
	if !strings.Contains(err.Error(), reports[0].ClientArtifactProfileID+"/"+reports[0].ServerArtifactProfileID) {
		t.Fatalf("incomplete error omitted matrix cell: %v", err)
	}
}

func TestGCENetworkingCellRejectsDNATAndBindEqualsDial(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	report := sampleNetworkingReportV3(checklist, "gce-one-to-one-nat")
	if err := ValidateReportV3(checklist, report); err != nil {
		t.Fatalf("valid GCE cell: %v", err)
	}
	if !CompleteNetworking(report) {
		t.Fatal("expected complete GCE networking evidence")
	}
	report.Networking.Binds.Data.Address = report.Networking.Dials.Data.Host
	if err := ValidateReportV3(checklist, report); err == nil {
		t.Fatal("accepted GCE cell with bind = dial")
	}
	report = sampleNetworkingReportV3(checklist, "gce-one-to-one-nat")
	report.Networking.TestDNATAbsent = false
	if err := ValidateReportV3(checklist, report); err == nil {
		t.Fatal("accepted GCE cell with test DNAT")
	}
	report = sampleNetworkingReportV3(checklist, "gce-one-to-one-nat")
	report.Networking.LoopbackAliasAbsent = false
	if err := ValidateReportV3(checklist, report); err == nil {
		t.Fatal("accepted GCE cell with lo alias")
	}
	report = sampleNetworkingReportV3(checklist, "gce-one-to-one-nat")
	report.Networking.ObservedListeners.Data = "0.0.0.0:2222"
	report.Networking.ObservedListeners.MatchBinds = true
	if err := ValidateReportV3(checklist, report); err == nil {
		t.Fatal("accepted GCE cell with unspecified observed listener")
	}
	report = sampleNetworkingReportV3(checklist, "gce-one-to-one-nat")
	report.Networking.InviteDials.Data.Host = report.Networking.Binds.Data.Address
	report.Networking.InviteDialsMatchPublished = false
	if err := ValidateReportV3(checklist, report); err == nil {
		t.Fatal("accepted GCE cell whose invite dials are the bind")
	}
}

func TestCleanTreeProofRejectsDirtyToken(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	report := sampleReportV3(checklist)
	report.CleanTreeProof = "dirty-ffff"
	report.Networking.CleanTree = false
	if err := ValidateReportV3(checklist, report); err != nil {
		t.Fatalf("dirty proof with clean_tree false should validate: %v", err)
	}
	if CompleteV3(report) {
		t.Fatal("dirty tree completed v3 evidence")
	}
}

func TestPassthroughNLBOptionalAndProxyForbidden(t *testing.T) {
	t.Parallel()

	checklist, err := LoadChecklistV3(DefaultChecklistV3Path(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	optional := false
	for _, cell := range checklist.NetworkingCells {
		if cell.ID == networkingCellPassthrough {
			optional = !cell.Required
		}
		if cell.PublicationModel == publicationProxyLB {
			t.Fatal("checklist includes a proxy-LB cell")
		}
	}
	if !optional {
		t.Fatal("passthrough NLB must be optional")
	}
	reports := completeIndexReportsV3(checklist)
	if err := ValidateIndexV3(checklist, reports); err != nil {
		t.Fatal(err)
	}
	passthrough := sampleNetworkingReportV3(checklist, networkingCellPassthrough)
	passthrough.Networking.PublicationModel = publicationPassthroughNLB
	passthrough.Networking.OperatorLoadBalancerAssumptions = "passthrough TCP NLB; backend terminates TLS/SSH; source quotas apply per LB"
	if err := ValidateReportV3(checklist, passthrough); err != nil {
		t.Fatalf("passthrough NLB cell: %v", err)
	}
	if err := ValidateIndexV3(checklist, append(reports, passthrough)); err != nil {
		t.Fatalf("optional passthrough in index: %v", err)
	}
}

func TestClientErrorClassesAreFrozen(t *testing.T) {
	t.Parallel()

	want := []string{
		locator.ClassDNSResolution,
		locator.ClassTCPConnect,
		locator.ClassTLSNegotiate,
		locator.ClassTLSSPKI,
		locator.ClassInviteAuthorization,
		locator.ClassSSHHostKey,
		locator.ClassForwardTarget,
	}
	if got := locator.ClientErrorClasses(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ClientErrorClasses=%v", got)
	}
}

func TestV3SchemaForbidsAdditionalPropertiesAndProxyModels(t *testing.T) {
	t.Parallel()

	schema := string(readRepoFile(t, filepath.Join(repositoryRoot(t), "schemas", "release-evidence-v3.schema.json")))
	if !strings.Contains(schema, `"additionalProperties": false`) {
		t.Fatal("v3 schema must set additionalProperties false")
	}
	if !strings.Contains(schema, `"const": 3`) {
		t.Fatal("v3 schema must pin schema_version 3")
	}
	for _, required := range []string{
		`"test_dnat_absent"`,
		`"loopback_alias_absent"`,
		`"enrollment_resolved_addr"`,
		`"data_resolved_addr"`,
		`"published_endpoint_generation"`,
		`"invite_dials"`,
		`"operator_firewall_assumptions"`,
		`"operator_load_balancer_assumptions"`,
		`"passthrough_nlb"`,
	} {
		if !strings.Contains(schema, required) {
			t.Errorf("v3 schema omits %s", required)
		}
	}
	for _, forbidden := range []string{`"proxy_lb"`, `"tls_termination"`, `"proxy_protocol"`} {
		if strings.Contains(schema, forbidden) {
			t.Errorf("v3 schema enumerates unsupported model %s", forbidden)
		}
	}
}

func sampleReportV3(checklist ChecklistV3) ReportV3 {
	return sampleMatrixReportV3(checklist, "darwin-arm64", "linux-amd64")
}

func sampleMatrixReportV3(checklist ChecklistV3, client, server string) ReportV3 {
	report := baseReportV3(checklist)
	report.ClientArtifactProfileID = client
	report.ServerArtifactProfileID = server
	if strings.Contains(client, "amd64") {
		report.ClientArchitecture = "amd64"
	}
	if strings.Contains(server, "arm64") {
		report.ServerArchitecture = "arm64"
	}
	report.CellClasses = []string{CellClassMatrix}
	report.Networking = sampleDirectNetworking()
	return report
}

func sampleNetworkingReportV3(checklist ChecklistV3, cellID string) ReportV3 {
	cell, ok := networkingCellByID(checklist, cellID)
	if !ok {
		panic("unknown cell " + cellID)
	}
	report := baseReportV3(checklist)
	report.CellClasses = []string{CellClassNetworking}
	report.Networking = sampleDirectNetworking()
	report.Networking.CellID = cell.ID
	report.Networking.PublicationModel = cell.PublicationModel
	if cell.ClientArtifactProfileID != "" {
		report.ClientArtifactProfileID = cell.ClientArtifactProfileID
	}
	if cell.ServerArtifactProfileID != "" {
		report.ServerArtifactProfileID = cell.ServerArtifactProfileID
		if strings.Contains(cell.ServerArtifactProfileID, "arm64") {
			report.ServerArchitecture = "arm64"
		}
	}
	switch cell.PublicationModel {
	case publicationOneToOneNAT, publicationPassthroughNLB:
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
		report.Networking.OperatorFirewallAssumptions = "GCE ingress tcp:2222,tcp:29722; no guest DNAT"
		report.Networking.OperatorLoadBalancerAssumptions = "none; 1:1 access-config NAT"
	case publicationPortMapped:
		report.Networking.Dials.Data.Port = 443
		report.Networking.Dials.Enrollment.Port = 443
		report.Networking.Dials.Enrollment.Host = "enroll.example.com"
		report.Networking.ClientDials[0].Port = 443
		report.Networking.ClientDials[1].Host = "enroll.example.com"
		report.Networking.ClientDials[1].Port = 443
		report.Networking.PublicationModel = publicationPortMapped
	case publicationDNSDial:
		report.Networking.Dials.Data.Host = "tunnel.example.com"
		report.Networking.Dials.Enrollment.Host = "enroll.example.com"
		report.Networking.ClientDials[0].Host = "tunnel.example.com"
		report.Networking.ClientDials[1].Host = "enroll.example.com"
		report.Networking.DataResolvedAddr = "34.20.174.226"
		report.Networking.EnrollmentResolvedAddr = "34.20.174.227"
	case publicationIPv6BindEquals:
		report.Networking.Binds.Data.Address = "2001:db8::2"
		report.Networking.Binds.Enrollment.Address = "2001:db8::2"
		report.Networking.Binds.Enrollment.Port = 29722
		report.Networking.Dials.Data.Host = "2001:db8::2"
		report.Networking.Dials.Enrollment.Host = "2001:db8::2"
		report.Networking.ObservedListeners.Data = "[2001:db8::2]:2222"
		report.Networking.ObservedListeners.Enrollment = "[2001:db8::2]:29722"
		report.Networking.ClientDials[0].Host = "2001:db8::2"
		report.Networking.ClientDials[1].Host = "2001:db8::2"
		report.Networking.DataResolvedAddr = "2001:db8::2"
		report.Networking.EnrollmentResolvedAddr = "2001:db8::2"
	}
	report.Networking.InviteDials = report.Networking.Dials
	report.Networking.InviteDialsMatchPublished = true
	return report
}

func completeIndexReportsV3(checklist ChecklistV3) []ReportV3 {
	var reports []ReportV3
	for _, cell := range RequiredMatrixCells(checklist.Checklist()) {
		reports = append(reports, sampleMatrixReportV3(checklist, cell.Client, cell.Server))
	}
	for _, cell := range RequiredNetworkingCells(checklist) {
		reports = append(reports, sampleNetworkingReportV3(checklist, cell.ID))
	}
	return reports
}

func baseReportV3(checklist ChecklistV3) ReportV3 {
	results := make([]Result, 0, len(checklist.Positive)+len(checklist.Negative))
	for _, item := range checklist.Positive {
		results = append(results, Result{ID: item.ID, Class: "positive", Status: "pass"})
	}
	for _, item := range checklist.Negative {
		results = append(results, Result{ID: item.ID, Class: "negative", Status: "pass"})
	}
	return ReportV3{
		Kind:                       Kind,
		SchemaVersion:              SchemaVersionV3,
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
		TestIdentity:               "v3-harness",
		Commands:                   []string{"./scripts/interop/orchestrate.sh"},
		StartedAt:                  "2026-08-24T00:00:00Z",
		FinishedAt:                 "2026-08-24T00:01:00Z",
		PackageToPackage:           true,
		SourceTreeSubstitution:     false,
		CellClasses:                []string{CellClassMatrix},
		Results:                    results,
		Networking:                 sampleDirectNetworking(),
	}
}

func sampleDirectNetworking() NetworkingEvidence {
	return NetworkingEvidence{
		PublicationModel:            publicationDirect,
		PublishedEndpointGeneration: 1,
		InviteSchemaVersion:         inviteSchemaV3,
		InviteDialsMatchPublished:   true,
		Binds: ServiceBindEvidence{
			Data:       BindEvidence{Address: "203.0.113.10", Port: 2222},
			Enrollment: BindEvidence{Address: "203.0.113.10", Port: 29722},
		},
		Dials: ServiceDialEvidence{
			Data:       DialEvidence{Host: "203.0.113.10", Port: 2222},
			Enrollment: DialEvidence{Host: "203.0.113.10", Port: 29722},
		},
		InviteDials: ServiceDialEvidence{
			Data:       DialEvidence{Host: "203.0.113.10", Port: 2222},
			Enrollment: DialEvidence{Host: "203.0.113.10", Port: 29722},
		},
		ObservedListeners: ObservedListenersEvidence{
			Data:       "203.0.113.10:2222",
			Enrollment: "203.0.113.10:29722",
			MatchBinds: true,
		},
		TestDNATAbsent:      true,
		LoopbackAliasAbsent: true,
		ClientDials: []ClientDialEvidence{
			{Leg: "data", Host: "203.0.113.10", Port: 2222, Status: "pass"},
			{Leg: "enrollment", Host: "203.0.113.10", Port: 29722, Status: "pass"},
		},
		SPKIResult:                      CheckEvidence{Status: "pass", Detail: "invite SPKI matched"},
		HostKeyResult:                   CheckEvidence{Status: "pass", Detail: "host key alias matched"},
		EnrollmentResolvedAddr:          "203.0.113.10",
		DataResolvedAddr:                "203.0.113.10",
		OperatorFirewallAssumptions:     "host firewall allows 2222/tcp and 29722/tcp",
		OperatorLoadBalancerAssumptions: "none; public address on the guest NIC",
		PackageOnly:                     true,
		CleanTree:                       true,
	}
}

func readRepoFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
