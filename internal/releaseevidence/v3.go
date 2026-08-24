package releaseevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/adoptionresult"
	"warptweet.com/warptweet/internal/locator"
)

const (
	// SchemaVersionV3 is the bind/dial networking release-evidence schema.
	SchemaVersionV3 = 3
)

const (
	publicationDirect         = "direct"
	publicationOneToOneNAT    = "one_to_one_nat"
	publicationPortMapped     = "port_mapped"
	publicationDNSDial        = "dns_dial"
	publicationIPv6BindEquals = "ipv6_bind_equals_dial"
	publicationPassthroughNLB = "passthrough_nlb"
	publicationProxyLB        = "proxy_lb"
	publicationTLSTermination = "tls_termination"
	publicationProxyProtocol  = "proxy_protocol"
	networkingCellGCEOneToOne = "gce-one-to-one-nat"
	networkingCellPassthrough = "passthrough-nlb"
	inviteSchemaV3            = 3
)

// allowedPublicationModels is the first-edition evidence set. Proxy load
// balancers, TLS termination, and PROXY protocol are not cells.
func allowedPublicationModels() map[string]struct{} {
	return map[string]struct{}{
		publicationDirect:         {},
		publicationOneToOneNAT:    {},
		publicationPortMapped:     {},
		publicationDNSDial:        {},
		publicationIPv6BindEquals: {},
		publicationPassthroughNLB: {},
	}
}

func forbiddenPublicationModels() map[string]struct{} {
	return map[string]struct{}{
		publicationProxyLB:        {},
		publicationTLSTermination: {},
		publicationProxyProtocol:  {},
	}
}

// NetworkingCell is one additional topology cell. It is not a matrix product.
type NetworkingCell struct {
	ID                              string `json:"id"`
	Title                           string `json:"title"`
	Required                        bool   `json:"required"`
	ClientArtifactProfileID         string `json:"client_artifact_profile_id,omitempty"`
	ServerArtifactProfileID         string `json:"server_artifact_profile_id,omitempty"`
	PublicationModel                string `json:"publication_model"`
	RequiresBindNeDataDial          bool   `json:"requires_bind_ne_data_dial"`
	RequiresInviteSchema            int    `json:"requires_invite_schema"`
	RequiresGuestListenersMatchBind bool   `json:"requires_guest_listeners_match_bind"`
	ForbidsTestDNAT                 bool   `json:"forbids_test_dnat"`
	ForbidsLoopbackAlias            bool   `json:"forbids_loopback_alias"`
}

// ChecklistV3 is the immutable v3 package-interop checklist plus networking cells.
type ChecklistV3 struct {
	Kind                     string           `json:"kind"`
	SchemaVersion            int              `json:"schema_version"`
	ProfileID                string           `json:"profile_id"`
	RequiresPackageToPackage bool             `json:"requires_package_to_package"`
	ForbidsSourceTreeSubst   bool             `json:"forbids_source_tree_substitution"`
	Positive                 []Case           `json:"positive"`
	Negative                 []Case           `json:"negative"`
	ArtifactBindingFields    []string         `json:"artifact_binding_fields"`
	Matrix                   Matrix           `json:"matrix"`
	NetworkingCells          []NetworkingCell `json:"networking_cells"`
	FileSHA256               string           `json:"-"`
}

// Checklist projects the shared case/matrix fields used by result validation.
func (checklist ChecklistV3) Checklist() Checklist {
	return Checklist{
		Kind:                     checklist.Kind,
		SchemaVersion:            checklist.SchemaVersion,
		ProfileID:                checklist.ProfileID,
		RequiresPackageToPackage: checklist.RequiresPackageToPackage,
		ForbidsSourceTreeSubst:   checklist.ForbidsSourceTreeSubst,
		Positive:                 checklist.Positive,
		Negative:                 checklist.Negative,
		ArtifactBindingFields:    checklist.ArtifactBindingFields,
		Matrix:                   checklist.Matrix,
		FileSHA256:               checklist.FileSHA256,
	}
}

// BindEvidence is one numeric guest bind.
type BindEvidence struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// DialEvidence is one published locator.
type DialEvidence struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// ServiceBindEvidence is data and enrollment binds.
type ServiceBindEvidence struct {
	Data       BindEvidence `json:"data"`
	Enrollment BindEvidence `json:"enrollment"`
}

// ServiceDialEvidence is data and enrollment published dials.
type ServiceDialEvidence struct {
	Data       DialEvidence `json:"data"`
	Enrollment DialEvidence `json:"enrollment"`
}

// ObservedListenersEvidence is what the guest actually accepted on.
type ObservedListenersEvidence struct {
	Data       string `json:"data"`
	Enrollment string `json:"enrollment"`
	MatchBinds bool   `json:"match_binds"`
}

// ClientDialEvidence is one client TCP/TLS/SSH attempt against a published dial.
type ClientDialEvidence struct {
	Leg        string `json:"leg"`
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	Status     string `json:"status"`
	ErrorClass string `json:"error_class,omitempty"`
}

// CheckEvidence is an SPKI or host-key observation.
type CheckEvidence struct {
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
}

// NetworkingEvidence is the v3 bind/dial observation block.
type NetworkingEvidence struct {
	CellID                          string                    `json:"cell_id"`
	PublicationModel                string                    `json:"publication_model"`
	PublishedEndpointGeneration     uint64                    `json:"published_endpoint_generation"`
	InviteSchemaVersion             int                       `json:"invite_schema_version"`
	InviteDialsMatchPublished       bool                      `json:"invite_dials_match_published"`
	InviteDials                     ServiceDialEvidence       `json:"invite_dials"`
	Binds                           ServiceBindEvidence       `json:"binds"`
	Dials                           ServiceDialEvidence       `json:"dials"`
	ObservedListeners               ObservedListenersEvidence `json:"observed_listeners"`
	TestDNATAbsent                  bool                      `json:"test_dnat_absent"`
	LoopbackAliasAbsent             bool                      `json:"loopback_alias_absent"`
	ClientDials                     []ClientDialEvidence      `json:"client_dials"`
	SPKIResult                      CheckEvidence             `json:"spki_result"`
	HostKeyResult                   CheckEvidence             `json:"host_key_result"`
	EnrollmentResolvedAddr          string                    `json:"enrollment_resolved_addr"`
	DataResolvedAddr                string                    `json:"data_resolved_addr"`
	OperatorFirewallAssumptions     string                    `json:"operator_firewall_assumptions"`
	OperatorLoadBalancerAssumptions string                    `json:"operator_load_balancer_assumptions"`
	PackageOnly                     bool                      `json:"package_only"`
	CleanTree                       bool                      `json:"clean_tree"`
}

// ReportV3 is one package-to-package evidence artifact for the v3 checklist.
type ReportV3 struct {
	Kind                       string             `json:"kind"`
	SchemaVersion              int                `json:"schema_version"`
	ContractID                 string             `json:"contract_id"`
	ContractChecklistSHA256    string             `json:"contract_checklist_sha256"`
	ReleaseVersion             string             `json:"release_version"`
	SourceCommit               string             `json:"source_commit"`
	CleanTreeProof             string             `json:"clean_tree_proof"`
	ClientPackageSHA256        string             `json:"client_package_sha256"`
	ServerPackageSHA256        string             `json:"server_package_sha256"`
	ClientPackagePath          string             `json:"client_package_path,omitempty"`
	ServerPackagePath          string             `json:"server_package_path,omitempty"`
	ClientArtifactProfileID    string             `json:"client_artifact_profile_id"`
	ServerArtifactProfileID    string             `json:"server_artifact_profile_id"`
	ClientEngineManifestSHA256 string             `json:"client_engine_manifest_sha256"`
	ServerEngineManifestSHA256 string             `json:"server_engine_manifest_sha256"`
	ClientPlatform             string             `json:"client_platform"`
	ServerPlatform             string             `json:"server_platform"`
	ClientArchitecture         string             `json:"client_architecture"`
	ServerArchitecture         string             `json:"server_architecture"`
	HostTarget                 string             `json:"host_target"`
	AuthorizationPolicy        string             `json:"authorization_policy"`
	RouteCount                 int                `json:"route_count"`
	RestartPolicies            []string           `json:"restart_policies"`
	TestIdentity               string             `json:"test_identity"`
	EvaluatorIdentity          string             `json:"evaluator_identity,omitempty"`
	Commands                   []string           `json:"commands"`
	StartedAt                  string             `json:"started_at"`
	FinishedAt                 string             `json:"finished_at"`
	RedactedLogPath            string             `json:"redacted_log_path,omitempty"`
	PackageToPackage           bool               `json:"package_to_package"`
	SourceTreeSubstitution     bool               `json:"source_tree_substitution"`
	CellClasses                []string           `json:"cell_classes"`
	Results                    []Result           `json:"results"`
	Networking                 NetworkingEvidence `json:"networking"`
}

// IndexV3 is the public-index document covering matrix and networking cells.
type IndexV3 struct {
	Kind                    string     `json:"kind"`
	SchemaVersion           int        `json:"schema_version"`
	ContractID              string     `json:"contract_id"`
	ContractChecklistSHA256 string     `json:"contract_checklist_sha256"`
	Reports                 []ReportV3 `json:"reports"`
}

// LoadChecklistV3 reads the v3 repository checklist document.
func LoadChecklistV3(path string) (ChecklistV3, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ChecklistV3{}, err
	}
	var checklist ChecklistV3
	if err := decodeStrict(raw, &checklist); err != nil {
		return ChecklistV3{}, err
	}
	sum := sha256.Sum256(raw)
	checklist.FileSHA256 = hex.EncodeToString(sum[:])
	if checklist.Kind != ChecklistKind || checklist.SchemaVersion != SchemaVersionV3 {
		return ChecklistV3{}, fmt.Errorf("unsupported checklist kind/version")
	}
	if !checklist.RequiresPackageToPackage || !checklist.ForbidsSourceTreeSubst {
		return ChecklistV3{}, fmt.Errorf("checklist must require package-to-package evidence")
	}
	if len(checklist.Positive) == 0 || len(checklist.Negative) == 0 {
		return ChecklistV3{}, fmt.Errorf("checklist must include positive and negative cases")
	}
	if len(RequiredMatrixCells(checklist.Checklist())) == 0 {
		return ChecklistV3{}, fmt.Errorf("checklist matrix is empty")
	}
	if err := validateNetworkingCells(checklist.NetworkingCells); err != nil {
		return ChecklistV3{}, err
	}
	return checklist, nil
}

func validateNetworkingCells(cells []NetworkingCell) error {
	if len(cells) == 0 {
		return fmt.Errorf("checklist must include networking cells")
	}
	seen := map[string]struct{}{}
	hasRequired := false
	hasGCE := false
	for _, cell := range cells {
		if strings.TrimSpace(cell.ID) == "" || strings.TrimSpace(cell.PublicationModel) == "" {
			return fmt.Errorf("networking cell id and publication_model are required")
		}
		if _, exists := seen[cell.ID]; exists {
			return fmt.Errorf("duplicate networking cell id %q", cell.ID)
		}
		seen[cell.ID] = struct{}{}
		if _, forbidden := forbiddenPublicationModels()[cell.PublicationModel]; forbidden {
			return fmt.Errorf("networking cell %q uses unsupported publication model %q", cell.ID, cell.PublicationModel)
		}
		if _, ok := allowedPublicationModels()[cell.PublicationModel]; !ok {
			return fmt.Errorf("networking cell %q has unknown publication model %q", cell.ID, cell.PublicationModel)
		}
		if cell.Required {
			hasRequired = true
		}
		if cell.ID == networkingCellGCEOneToOne {
			hasGCE = true
			if !cell.Required {
				return fmt.Errorf("networking cell %q must be required", cell.ID)
			}
			if cell.PublicationModel != publicationOneToOneNAT {
				return fmt.Errorf("networking cell %q must use publication model %q", cell.ID, publicationOneToOneNAT)
			}
			if !cell.RequiresBindNeDataDial || !cell.ForbidsTestDNAT || !cell.ForbidsLoopbackAlias {
				return fmt.Errorf("networking cell %q must require bind≠dial and forbid test DNAT/lo aliases", cell.ID)
			}
		}
		if cell.ID == networkingCellPassthrough && cell.Required {
			return fmt.Errorf("passthrough NLB is an optional evidence cell")
		}
		if cell.RequiresInviteSchema != 0 && cell.RequiresInviteSchema != inviteSchemaV3 {
			return fmt.Errorf("networking cell %q invite schema must be %d", cell.ID, inviteSchemaV3)
		}
	}
	if !hasRequired {
		return fmt.Errorf("checklist must include at least one required networking cell")
	}
	if !hasGCE {
		return fmt.Errorf("checklist must include the GCE 1:1 NAT networking cell")
	}
	return nil
}

// DefaultChecklistV3Path returns the repository v3 checklist path.
func DefaultChecklistV3Path(repositoryRoot string) string {
	return filepath.Join(repositoryRoot, "packaging", "evidence", "checklist-v3.json")
}

// DecodeReportV3 strictly decodes one v3 evidence document.
func DecodeReportV3(raw []byte) (ReportV3, error) {
	var report ReportV3
	if err := decodeStrict(raw, &report); err != nil {
		return ReportV3{}, err
	}
	return report, nil
}

// DecodeIndexV3 strictly decodes one v3 public-index document.
func DecodeIndexV3(raw []byte) (IndexV3, error) {
	var index IndexV3
	if err := decodeStrict(raw, &index); err != nil {
		return IndexV3{}, err
	}
	return index, nil
}

// WriteReportV3 validates report and only then writes path atomically.
func WriteReportV3(path string, checklist ChecklistV3, report ReportV3) error {
	if err := ValidateReportV3(checklist, report); err != nil {
		return err
	}
	return writeJSONAtomically(path, report)
}

// WriteIndexV3 validates the index and only then writes path atomically.
func WriteIndexV3(path string, checklist ChecklistV3, index IndexV3) error {
	if err := ValidateIndexDocumentV3(checklist, index); err != nil {
		return err
	}
	return writeJSONAtomically(path, index)
}

func writeJSONAtomically(path string, document any) error {
	if path == "" {
		return fmt.Errorf("evidence output path is required")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("evidence output already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".warptweet-evidence-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ValidateReportV3 checks one v3 evidence report against the v3 checklist.
func ValidateReportV3(checklist ChecklistV3, report ReportV3) error {
	if report.Kind != Kind || report.SchemaVersion != SchemaVersionV3 {
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
	if err := validateCleanTree(report); err != nil {
		return err
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
	if err := validateCellClasses(report.CellClasses); err != nil {
		return err
	}
	if err := validateResults(checklist.Checklist(), report.Results); err != nil {
		return err
	}
	return validateNetworkingEvidence(checklist, report)
}

func validateCellClasses(classes []string) error {
	if len(classes) == 0 {
		return fmt.Errorf("cell_classes must be non-empty")
	}
	seen := map[string]struct{}{}
	for _, class := range classes {
		switch class {
		case CellClassMatrix, CellClassNetworking:
		default:
			return fmt.Errorf("invalid cell class %q", class)
		}
		if _, exists := seen[class]; exists {
			return fmt.Errorf("duplicate cell class %q", class)
		}
		seen[class] = struct{}{}
	}
	return nil
}

func validateResults(checklist Checklist, results []Result) error {
	required := map[string]string{}
	for _, item := range checklist.Positive {
		required[item.ID] = "positive"
	}
	for _, item := range checklist.Negative {
		required[item.ID] = "negative"
	}
	seen := map[string]Result{}
	for _, result := range results {
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

func validateNetworkingEvidence(checklist ChecklistV3, report ReportV3) error {
	net := report.Networking
	if _, forbidden := forbiddenPublicationModels()[net.PublicationModel]; forbidden {
		return fmt.Errorf("publication model %q is not a first-edition evidence cell", net.PublicationModel)
	}
	if _, ok := allowedPublicationModels()[net.PublicationModel]; !ok {
		return fmt.Errorf("unknown publication model %q", net.PublicationModel)
	}
	if net.PublishedEndpointGeneration == 0 {
		return fmt.Errorf("published_endpoint_generation must be at least 1")
	}
	if net.InviteSchemaVersion != inviteSchemaV3 {
		return fmt.Errorf("invite_schema_version must be %d", inviteSchemaV3)
	}
	if strings.TrimSpace(net.OperatorFirewallAssumptions) == "" {
		return fmt.Errorf("operator_firewall_assumptions is required")
	}
	if strings.TrimSpace(net.OperatorLoadBalancerAssumptions) == "" {
		return fmt.Errorf("operator_load_balancer_assumptions is required")
	}
	if err := validateBindEvidence("data", net.Binds.Data); err != nil {
		return err
	}
	if err := validateBindEvidence("enrollment", net.Binds.Enrollment); err != nil {
		return err
	}
	if err := validateDialEvidence("data", net.Dials.Data); err != nil {
		return err
	}
	if err := validateDialEvidence("enrollment", net.Dials.Enrollment); err != nil {
		return err
	}
	if err := validateDialEvidence("invite data", net.InviteDials.Data); err != nil {
		return err
	}
	if err := validateDialEvidence("invite enrollment", net.InviteDials.Enrollment); err != nil {
		return err
	}
	if bindKey(net.Binds.Data) == bindKey(net.Binds.Enrollment) {
		return fmt.Errorf("data and enrollment binds must not share the same address:port")
	}
	if dialKey(net.Dials.Data) == dialKey(net.Dials.Enrollment) {
		return fmt.Errorf("data and enrollment dials must not share the same host:port")
	}
	if strings.TrimSpace(net.ObservedListeners.Data) == "" || strings.TrimSpace(net.ObservedListeners.Enrollment) == "" {
		return fmt.Errorf("observed listeners are required")
	}
	listenersMatch := observedListenersMatchBinds(net)
	if net.ObservedListeners.MatchBinds != listenersMatch {
		if net.ObservedListeners.MatchBinds {
			return fmt.Errorf("observed listeners do not match binds")
		}
		return fmt.Errorf("match_binds is false but observed listeners match binds")
	}
	inviteMatch := inviteDialsMatchPublished(net)
	if net.InviteDialsMatchPublished != inviteMatch {
		if net.InviteDialsMatchPublished {
			return fmt.Errorf("invite dials do not match published dials")
		}
		return fmt.Errorf("invite_dials_match_published is false but invite dials match published dials")
	}
	if err := validateClientDials(net); err != nil {
		return err
	}
	if err := validateCheckEvidence("spki_result", net.SPKIResult); err != nil {
		return err
	}
	if err := validateCheckEvidence("host_key_result", net.HostKeyResult); err != nil {
		return err
	}
	if reportHasCellClass(report, CellClassNetworking) {
		if strings.TrimSpace(net.CellID) == "" {
			return fmt.Errorf("networking cell reports require networking.cell_id")
		}
		cell, ok := networkingCellByID(checklist, net.CellID)
		if !ok {
			return fmt.Errorf("unknown networking cell id %q", net.CellID)
		}
		if net.PublicationModel != cell.PublicationModel {
			return fmt.Errorf("networking cell %q publication model %q does not match checklist %q", cell.ID, net.PublicationModel, cell.PublicationModel)
		}
		if cell.ClientArtifactProfileID != "" && report.ClientArtifactProfileID != cell.ClientArtifactProfileID {
			return fmt.Errorf("networking cell %q requires client profile %s", cell.ID, cell.ClientArtifactProfileID)
		}
		if cell.ServerArtifactProfileID != "" && report.ServerArtifactProfileID != cell.ServerArtifactProfileID {
			return fmt.Errorf("networking cell %q requires server profile %s", cell.ID, cell.ServerArtifactProfileID)
		}
		if cell.RequiresBindNeDataDial && bindEqualsDial(net.Binds.Data, net.Dials.Data) {
			return fmt.Errorf("networking cell %q requires data bind ≠ data dial", cell.ID)
		}
		if cell.RequiresGuestListenersMatchBind && !listenersMatch {
			return fmt.Errorf("networking cell %q requires guest listeners to match binds", cell.ID)
		}
		if cell.ForbidsTestDNAT && !net.TestDNATAbsent {
			return fmt.Errorf("networking cell %q forbids test DNAT", cell.ID)
		}
		if cell.ForbidsLoopbackAlias && !net.LoopbackAliasAbsent {
			return fmt.Errorf("networking cell %q forbids loopback aliases", cell.ID)
		}
		if cell.RequiresInviteSchema != 0 && net.InviteSchemaVersion != cell.RequiresInviteSchema {
			return fmt.Errorf("networking cell %q requires invite schema %d", cell.ID, cell.RequiresInviteSchema)
		}
		if cell.ID == networkingCellGCEOneToOne && !inviteMatch {
			return fmt.Errorf("networking cell %q requires invite schema-3 dials to match published dials", cell.ID)
		}
	} else if net.CellID != "" {
		if _, ok := networkingCellByID(checklist, net.CellID); !ok {
			return fmt.Errorf("unknown networking cell id %q", net.CellID)
		}
	}
	if net.PublicationModel == publicationDNSDial {
		if isIPLiteral(net.Dials.Data.Host) {
			return fmt.Errorf("dns_dial data host must be a DNS name")
		}
	}
	if net.PublicationModel == publicationIPv6BindEquals {
		if !bindEqualsDial(net.Binds.Data, net.Dials.Data) {
			return fmt.Errorf("ipv6_bind_equals_dial requires data bind = data dial")
		}
		addr, err := netip.ParseAddr(net.Binds.Data.Address)
		if err != nil || !addr.Is6() {
			return fmt.Errorf("ipv6_bind_equals_dial requires an IPv6 bind address")
		}
	}
	return nil
}

func validateBindEvidence(label string, endpoint BindEvidence) error {
	if strings.TrimSpace(endpoint.Address) == "" {
		return fmt.Errorf("%s bind address is required", label)
	}
	addr, err := netip.ParseAddr(endpoint.Address)
	if err != nil {
		return fmt.Errorf("%s bind address must be a numeric IP", label)
	}
	if addr.IsUnspecified() {
		return fmt.Errorf("%s bind address must not be unspecified", label)
	}
	if endpoint.Port < 1 {
		return fmt.Errorf("%s bind port must be between 1 and 65535", label)
	}
	return nil
}

func validateDialEvidence(label string, endpoint DialEvidence) error {
	if strings.TrimSpace(endpoint.Host) == "" {
		return fmt.Errorf("%s dial host is required", label)
	}
	if _, err := locator.ParseDialHost(endpoint.Host); err != nil {
		return fmt.Errorf("%s dial host: %w", label, err)
	}
	if endpoint.Port < 1 {
		return fmt.Errorf("%s dial port must be between 1 and 65535", label)
	}
	return nil
}

func validateClientDials(net NetworkingEvidence) error {
	if len(net.ClientDials) < 2 {
		return fmt.Errorf("client_dials must include data and enrollment legs")
	}
	seenLeg := map[string]struct{}{}
	allowed := map[string]struct{}{}
	for _, class := range locator.ClientErrorClasses() {
		allowed[class] = struct{}{}
	}
	for _, dial := range net.ClientDials {
		switch dial.Leg {
		case "data", "enrollment":
		default:
			return fmt.Errorf("client dial leg %q is invalid", dial.Leg)
		}
		if _, exists := seenLeg[dial.Leg]; exists {
			return fmt.Errorf("duplicate client dial leg %q", dial.Leg)
		}
		seenLeg[dial.Leg] = struct{}{}
		if strings.TrimSpace(dial.Host) == "" || dial.Port < 1 {
			return fmt.Errorf("client dial %s host and port are required", dial.Leg)
		}
		switch dial.Status {
		case "pass", "fail", "not_run":
		default:
			return fmt.Errorf("client dial %s has invalid status %q", dial.Leg, dial.Status)
		}
		if err := validateErrorClass(dial.Status, dial.ErrorClass, allowed); err != nil {
			return fmt.Errorf("client dial %s: %w", dial.Leg, err)
		}
		want := net.Dials.Data
		if dial.Leg == "enrollment" {
			want = net.Dials.Enrollment
		}
		if dial.Host != want.Host || dial.Port != want.Port {
			return fmt.Errorf("client dial %s must use the published dial %s:%d", dial.Leg, want.Host, want.Port)
		}
	}
	if _, ok := seenLeg["data"]; !ok {
		return fmt.Errorf("client_dials missing data leg")
	}
	if _, ok := seenLeg["enrollment"]; !ok {
		return fmt.Errorf("client_dials missing enrollment leg")
	}
	return nil
}

func validateCheckEvidence(field string, check CheckEvidence) error {
	switch check.Status {
	case "pass", "fail", "not_run":
	default:
		return fmt.Errorf("%s has invalid status %q", field, check.Status)
	}
	allowed := map[string]struct{}{}
	for _, class := range locator.ClientErrorClasses() {
		allowed[class] = struct{}{}
	}
	if err := validateErrorClass(check.Status, check.ErrorClass, allowed); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func validateErrorClass(status, class string, allowed map[string]struct{}) error {
	if status == "fail" {
		if class == "" {
			return fmt.Errorf("fail requires error_class")
		}
		if _, ok := allowed[class]; !ok {
			return fmt.Errorf("unknown error class %q", class)
		}
		return nil
	}
	if class != "" {
		return fmt.Errorf("error_class is only valid on fail")
	}
	return nil
}

func networkingCellByID(checklist ChecklistV3, id string) (NetworkingCell, bool) {
	for _, cell := range checklist.NetworkingCells {
		if cell.ID == id {
			return cell, true
		}
	}
	return NetworkingCell{}, false
}

func reportHasCellClass(report ReportV3, class string) bool {
	for _, item := range report.CellClasses {
		if item == class {
			return true
		}
	}
	return false
}

func bindKey(endpoint BindEvidence) string {
	addr, err := netip.ParseAddr(endpoint.Address)
	if err != nil {
		return endpoint.Address + "\x00" + fmt.Sprintf("%d", endpoint.Port)
	}
	return addr.Unmap().String() + "\x00" + fmt.Sprintf("%d", endpoint.Port)
}

func dialKey(endpoint DialEvidence) string {
	host, err := locator.ParseDialHost(endpoint.Host)
	if err != nil {
		return strings.ToLower(endpoint.Host) + "\x00" + fmt.Sprintf("%d", endpoint.Port)
	}
	canonical, err := host.Canonical()
	if err != nil {
		return strings.ToLower(endpoint.Host) + "\x00" + fmt.Sprintf("%d", endpoint.Port)
	}
	return canonical + "\x00" + fmt.Sprintf("%d", endpoint.Port)
}

func bindEqualsDial(bind BindEvidence, dial DialEvidence) bool {
	return bindKey(bind) == dialKey(dial)
}

func observedListenersMatchBinds(net NetworkingEvidence) bool {
	return listenerMatchesBind(net.ObservedListeners.Data, net.Binds.Data) &&
		listenerMatchesBind(net.ObservedListeners.Enrollment, net.Binds.Enrollment)
}

func inviteDialsMatchPublished(net NetworkingEvidence) bool {
	return dialKey(net.InviteDials.Data) == dialKey(net.Dials.Data) &&
		dialKey(net.InviteDials.Enrollment) == dialKey(net.Dials.Enrollment)
}

func listenerMatchesBind(observed string, bind BindEvidence) bool {
	parsed, err := parseListener(observed)
	if err != nil {
		return false
	}
	return bindKey(parsed) == bindKey(bind)
}

func parseListener(value string) (BindEvidence, error) {
	value = strings.TrimSpace(value)
	var host, portText string
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 || end+1 >= len(value) || value[end+1] != ':' {
			return BindEvidence{}, fmt.Errorf("invalid IPv6 listener %q", value)
		}
		host = value[1:end]
		portText = value[end+2:]
	} else {
		index := strings.LastIndex(value, ":")
		if index <= 0 || index == len(value)-1 {
			return BindEvidence{}, fmt.Errorf("invalid listener %q", value)
		}
		host = value[:index]
		portText = value[index+1:]
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port < 1 {
		return BindEvidence{}, fmt.Errorf("invalid listener port %q", value)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return BindEvidence{}, fmt.Errorf("listener host must be a numeric IP: %q", value)
	}
	if addr.IsUnspecified() {
		return BindEvidence{}, fmt.Errorf("unspecified listener %q does not match a concrete bind", value)
	}
	return BindEvidence{Address: addr.Unmap().String(), Port: uint16(port)}, nil
}

func cleanTreeProofAccepted(proof string) bool {
	return proof == "clean" || proof == "git-status-empty"
}

func validateCleanTree(report ReportV3) error {
	accepted := cleanTreeProofAccepted(report.CleanTreeProof)
	if report.Networking.CleanTree && !accepted {
		return fmt.Errorf("clean_tree requires clean_tree_proof of clean or git-status-empty")
	}
	if accepted && !report.Networking.CleanTree {
		return fmt.Errorf("clean_tree_proof %q requires networking.clean_tree", report.CleanTreeProof)
	}
	return nil
}

func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// CompleteV3 reports whether every v3 checklist case passed and the report is package-only.
func CompleteV3(report ReportV3) bool {
	if len(report.Results) == 0 {
		return false
	}
	for _, result := range report.Results {
		if result.Status != "pass" {
			return false
		}
	}
	return report.PackageToPackage && !report.SourceTreeSubstitution &&
		report.Networking.PackageOnly && report.Networking.CleanTree &&
		cleanTreeProofAccepted(report.CleanTreeProof) &&
		report.Networking.TestDNATAbsent && report.Networking.LoopbackAliasAbsent &&
		observedListenersMatchBinds(report.Networking) &&
		inviteDialsMatchPublished(report.Networking)
}

// CompleteNetworking reports whether topology evidence for a networking cell passed.
func CompleteNetworking(report ReportV3) bool {
	net := report.Networking
	if !report.PackageToPackage || report.SourceTreeSubstitution {
		return false
	}
	if !net.PackageOnly || !net.CleanTree || !cleanTreeProofAccepted(report.CleanTreeProof) ||
		!net.TestDNATAbsent || !net.LoopbackAliasAbsent {
		return false
	}
	if !inviteDialsMatchPublished(net) || !observedListenersMatchBinds(net) {
		return false
	}
	if net.SPKIResult.Status != "pass" || net.HostKeyResult.Status != "pass" {
		return false
	}
	if strings.TrimSpace(net.EnrollmentResolvedAddr) == "" || strings.TrimSpace(net.DataResolvedAddr) == "" {
		return false
	}
	if len(net.ClientDials) < 2 {
		return false
	}
	for _, dial := range net.ClientDials {
		if dial.Status != "pass" {
			return false
		}
	}
	return true
}

// RequiredNetworkingCells returns required additional topology cells.
func RequiredNetworkingCells(checklist ChecklistV3) []NetworkingCell {
	var cells []NetworkingCell
	for _, cell := range checklist.NetworkingCells {
		if cell.Required {
			cells = append(cells, cell)
		}
	}
	return cells
}

// ValidateIndexDocumentV3 checks an index envelope and its reports.
func ValidateIndexDocumentV3(checklist ChecklistV3, index IndexV3) error {
	if index.Kind != IndexKind || index.SchemaVersion != SchemaVersionV3 {
		return fmt.Errorf("unsupported evidence index kind/version")
	}
	if index.ContractID != adoptionresult.ContractID {
		return fmt.Errorf("contract_id must be %q", adoptionresult.ContractID)
	}
	if checklist.FileSHA256 != "" && index.ContractChecklistSHA256 != checklist.FileSHA256 {
		return fmt.Errorf("contract_checklist_sha256 must be the SHA-256 of the canonical checklist file")
	}
	return ValidateIndexV3(checklist, index.Reports)
}

// ValidateIndexV3 checks matrix coverage plus additional networking cells.
func ValidateIndexV3(checklist ChecklistV3, reports []ReportV3) error {
	requiredMatrix := map[string]struct{}{}
	for _, cell := range RequiredMatrixCells(checklist.Checklist()) {
		requiredMatrix[cell.Client+"/"+cell.Server] = struct{}{}
	}
	if len(requiredMatrix) == 0 {
		return fmt.Errorf("checklist matrix is empty")
	}
	requiredNetworking := map[string]NetworkingCell{}
	optionalNetworking := map[string]NetworkingCell{}
	for _, cell := range checklist.NetworkingCells {
		if cell.Required {
			requiredNetworking[cell.ID] = cell
		} else {
			optionalNetworking[cell.ID] = cell
		}
	}
	seenMatrix := map[string]struct{}{}
	seenNetworking := map[string]struct{}{}
	for i, report := range reports {
		if err := ValidateReportV3(checklist, report); err != nil {
			return fmt.Errorf("report %d: %w", i, err)
		}
		if reportHasCellClass(report, CellClassMatrix) {
			key := report.ClientArtifactProfileID + "/" + report.ServerArtifactProfileID
			if _, ok := requiredMatrix[key]; !ok {
				return fmt.Errorf("unknown matrix cell %s", key)
			}
			if _, exists := seenMatrix[key]; exists {
				return fmt.Errorf("duplicate matrix cell %s", key)
			}
			seenMatrix[key] = struct{}{}
		}
		if reportHasCellClass(report, CellClassNetworking) {
			id := report.Networking.CellID
			if _, required := requiredNetworking[id]; !required {
				if _, optional := optionalNetworking[id]; !optional {
					return fmt.Errorf("unknown networking cell %s", id)
				}
			}
			if _, exists := seenNetworking[id]; exists {
				return fmt.Errorf("duplicate networking cell %s", id)
			}
			seenNetworking[id] = struct{}{}
		}
	}
	var missingMatrix []string
	for _, cell := range RequiredMatrixCells(checklist.Checklist()) {
		key := cell.Client + "/" + cell.Server
		if _, ok := seenMatrix[key]; !ok {
			missingMatrix = append(missingMatrix, key)
		}
	}
	sort.Strings(missingMatrix)
	if len(missingMatrix) > 0 {
		return fmt.Errorf("missing matrix cells: %s", strings.Join(missingMatrix, ", "))
	}
	var missingNetworking []string
	for _, cell := range RequiredNetworkingCells(checklist) {
		if _, ok := seenNetworking[cell.ID]; !ok {
			missingNetworking = append(missingNetworking, cell.ID)
		}
	}
	sort.Strings(missingNetworking)
	if len(missingNetworking) > 0 {
		return fmt.Errorf("missing networking cells: %s", strings.Join(missingNetworking, ", "))
	}
	return nil
}

// CompleteIndexV3 reports whether every required matrix and networking cell passed.
func CompleteIndexV3(checklist ChecklistV3, reports []ReportV3) bool {
	if len(reports) == 0 {
		return false
	}
	if err := ValidateIndexV3(checklist, reports); err != nil {
		return false
	}
	for _, report := range reports {
		if reportHasCellClass(report, CellClassMatrix) && !CompleteV3(report) {
			return false
		}
		if reportHasCellClass(report, CellClassNetworking) && !CompleteNetworking(report) {
			return false
		}
	}
	return true
}

// BindArtifactDigestsV3 hashes the named package files and requires they match the report.
func BindArtifactDigestsV3(repositoryRoot string, report ReportV3) error {
	v2 := ReportV2{
		ClientPackagePath:   report.ClientPackagePath,
		ServerPackagePath:   report.ServerPackagePath,
		ClientPackageSHA256: report.ClientPackageSHA256,
		ServerPackageSHA256: report.ServerPackageSHA256,
	}
	return BindArtifactDigests(repositoryRoot, v2)
}
