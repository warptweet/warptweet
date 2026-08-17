package adoptionresult

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestValidateDocumentRejectsUnknownAndDigestMismatch(t *testing.T) {
	t.Parallel()

	base := validDocument()
	if err := ValidateDocument(base); err != nil {
		t.Fatalf("valid document: %v", err)
	}
	base.ContractChecklistSHA256 = strings.Repeat("a", 64)
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted digest mismatch")
	}
	base = validDocument()
	base.Results = append(base.Results, Result{ID: "SCOPE-001", Status: "fail"})
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted duplicate id")
	}
	base = validDocument()
	base.Results[0].ID = "NOT-A-REAL-ID"
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted unknown id")
	}
	base = validDocument()
	base.Results[0].Status = "waived"
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted unknown status")
	}
	base = validDocument()
	base.Results[0].Status = "pass"
	base.Results[0].Evidence = nil
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted pass without evidence")
	}
}

func TestDecodeStrictRejectsUnknownFieldsAndTrailing(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(validDocument())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict(append(raw, []byte("\n{}\n")...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if _, err := DecodeStrict([]byte(`{"kind":"warptweet.adoption-release-result","schema_version":1,"extra":true}`)); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestChecklistDigestMatchesContractFile(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("sed", "-n",
		`/^<!-- BEGIN WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->$/,/^<!-- END WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->$/p`,
		"docs/2026-08-16_adoption-and-release-strategy.md")
	cmd.Dir = repositoryRoot(t)
	block, err := cmd.Output()
	if err != nil {
		t.Fatalf("extract checklist: %v", err)
	}
	if err := VerifyChecklistDigest(block); err != nil {
		t.Fatal(err)
	}
}

func validDocument() Document {
	results := make([]Result, 0, len(requiredIDs))
	for _, id := range requiredIDs {
		results = append(results, Result{ID: id, Status: "not_run", Notes: "source implementation in progress"})
	}
	return Document{
		Kind:                    Kind,
		SchemaVersion:           SchemaVersion,
		ContractID:              ContractID,
		ContractChecklistSHA256: ContractChecklistSHA256,
		SourceCommit:            strings.Repeat("a", 40),
		ReleaseVersion:          "0.1.0-dev",
		Results:                 results,
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(wd + "/docs/2026-08-16_adoption-and-release-strategy.md"); err == nil {
			return wd
		}
		parent := wd[:strings.LastIndex(wd, "/")]
		if parent == wd || parent == "" {
			t.Fatal("repository root not found")
		}
		wd = parent
	}
}
