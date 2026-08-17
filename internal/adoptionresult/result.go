// Package adoptionresult validates adoption-release review results against the
// immutable v1 ledger. It never edits the contract.
package adoptionresult

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// Kind is the adoption-release result document kind.
	Kind = "warptweet.adoption-release-result"
	// SchemaVersion is the only supported result schema.
	SchemaVersion = 1
	// ContractID is the immutable v1 adoption-release contract.
	ContractID = "warptweet.adoption-release.v1"
	// ContractChecklistSHA256 is the SHA-256 of the canonical checklist block.
	ContractChecklistSHA256 = "5fa66b60627b8cf2dc4720d14719c8368f6749cbd0ebc262d1990ebd4b95b2e3"
	maxResultBytes          = 1 << 20
)

// Result is one ledger item evaluation.
type Result struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// Document is one complete adoption-release review result.
type Document struct {
	Kind                    string   `json:"kind"`
	SchemaVersion           int      `json:"schema_version"`
	ContractID              string   `json:"contract_id"`
	ContractChecklistSHA256 string   `json:"contract_checklist_sha256"`
	SourceCommit            string   `json:"source_commit"`
	ReleaseVersion          string   `json:"release_version"`
	Results                 []Result `json:"results"`
}

// RequiredIDs is the immutable v1 ledger in document order.
func RequiredIDs() []string {
	return append([]string(nil), requiredIDs...)
}

// ValidateDocument checks one result document against the v1 ledger.
func ValidateDocument(document Document) error {
	if document.Kind != Kind || document.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported adoption-release result kind/version")
	}
	if document.ContractID != ContractID {
		return fmt.Errorf("contract_id must be %q", ContractID)
	}
	if document.ContractChecklistSHA256 != ContractChecklistSHA256 {
		return fmt.Errorf("contract_checklist_sha256 does not match the v1 ledger digest")
	}
	if len(document.SourceCommit) != 40 || !isLowerHex(document.SourceCommit) {
		return fmt.Errorf("source_commit must be 40 lowercase hex characters")
	}
	if strings.TrimSpace(document.ReleaseVersion) == "" {
		return fmt.Errorf("release_version is required")
	}
	required := map[string]struct{}{}
	for _, id := range requiredIDs {
		required[id] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, result := range document.Results {
		if _, ok := required[result.ID]; !ok {
			return fmt.Errorf("unknown result id %q", result.ID)
		}
		if _, exists := seen[result.ID]; exists {
			return fmt.Errorf("duplicate result id %q", result.ID)
		}
		seen[result.ID] = struct{}{}
		switch result.Status {
		case "pass", "fail", "blocked", "not_run":
		default:
			return fmt.Errorf("result %q has invalid status %q", result.ID, result.Status)
		}
		if result.Status == "pass" && len(result.Evidence) == 0 {
			return fmt.Errorf("result %q pass requires evidence", result.ID)
		}
	}
	if len(seen) != len(required) {
		missing := make([]string, 0, len(required))
		for _, id := range requiredIDs {
			if _, ok := seen[id]; !ok {
				missing = append(missing, id)
			}
		}
		return fmt.Errorf("missing checklist results: %s", strings.Join(missing, ", "))
	}
	return nil
}

// DecodeStrict parses one bounded result document.
func DecodeStrict(raw []byte) (Document, error) {
	if len(raw) == 0 || len(raw) > maxResultBytes {
		return Document{}, fmt.Errorf("adoption-release result is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, err
	}
	if decoder.More() {
		return Document{}, fmt.Errorf("trailing JSON values")
	}
	if err := ValidateDocument(document); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Load reads and validates one result document.
func Load(path string) (Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return DecodeStrict(raw)
}

// VerifyChecklistDigest checks the canonical checklist block digest.
func VerifyChecklistDigest(block []byte) error {
	sum := sha256.Sum256(block)
	got := hex.EncodeToString(sum[:])
	if got != ContractChecklistSHA256 {
		return fmt.Errorf("checklist digest %s does not match v1 %s", got, ContractChecklistSHA256)
	}
	return nil
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

var requiredIDs = []string{
	"SCOPE-001", "SCOPE-002", "SCOPE-003", "SCOPE-004", "SCOPE-005", "SCOPE-006", "SCOPE-007", "SCOPE-008",
	"CLIENT-001", "CLIENT-002", "CLIENT-003", "CLIENT-004", "CLIENT-005", "CLIENT-006", "CLIENT-007", "CLIENT-008",
	"CLIENT-009", "CLIENT-010", "CLIENT-011", "CLIENT-012", "CLIENT-013", "CLIENT-014", "CLIENT-015", "CLIENT-016",
	"PRIV-001", "PRIV-002", "PRIV-003", "PRIV-004", "PRIV-005", "PRIV-006", "PRIV-007", "PRIV-008", "PRIV-009",
	"LEASE-001", "LEASE-002", "LEASE-003", "LEASE-004", "LEASE-005", "LEASE-006", "LEASE-007", "LEASE-008",
	"LEASE-009", "LEASE-010", "LEASE-011", "LEASE-012", "LEASE-013", "LEASE-014", "LEASE-015", "LEASE-016", "LEASE-017",
	"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-008", "SEC-009", "SEC-010", "SEC-011",
	"PKG-001", "PKG-002", "PKG-003", "PKG-004", "PKG-005", "PKG-006", "PKG-007", "PKG-008", "PKG-009", "PKG-010", "PKG-011", "PKG-012",
	"WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005", "WEB-006", "WEB-007", "WEB-008", "WEB-009", "WEB-010",
	"WEB-011", "WEB-012", "WEB-013", "WEB-014", "WEB-015", "WEB-016",
	"VERIFY-001", "VERIFY-002", "VERIFY-003", "VERIFY-004", "VERIFY-005", "VERIFY-006", "VERIFY-007", "VERIFY-008",
	"VERIFY-009", "VERIFY-010", "VERIFY-011", "VERIFY-012",
}

// Missing returns the ledger ids absent from seen, in ledger order.
func Missing(seen map[string]struct{}) []string {
	missing := make([]string, 0)
	for _, id := range requiredIDs {
		if _, ok := seen[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}
