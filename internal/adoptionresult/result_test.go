package adoptionresult

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	base = validDocument()
	base.Results = base.Results[1:]
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted incomplete ledger")
	}
	base = validDocument()
	base.SourceCommit = "not-a-commit"
	if err := ValidateDocument(base); err == nil {
		t.Fatal("accepted malformed source_commit")
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

	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "2026-08-16_adoption-and-release-strategy.md"))
	if err != nil {
		t.Fatalf("read strategy document: %v", err)
	}
	block, err := extractChecklistBlock(raw)
	if err != nil {
		t.Fatalf("extract checklist: %v", err)
	}
	if err := VerifyChecklistDigest(block); err != nil {
		t.Fatal(err)
	}

	crlf := bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n"))
	crlfBlock, err := extractChecklistBlock(crlf)
	if err != nil {
		t.Fatalf("extract checklist from CRLF input: %v", err)
	}
	if !bytes.Contains(crlfBlock, []byte("<!-- BEGIN WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->")) {
		t.Fatal("CRLF extraction missed begin marker")
	}
	if !bytes.Contains(crlfBlock, []byte("<!-- END WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->")) {
		t.Fatal("CRLF extraction missed end marker")
	}
}

func extractChecklistBlock(raw []byte) ([]byte, error) {
	const begin = "<!-- BEGIN WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->"
	const end = "<!-- END WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->"
	var out bytes.Buffer
	inBlock := false
	for _, line := range bytes.SplitAfter(raw, []byte("\n")) {
		text := bytes.TrimRight(line, "\r\n")
		if bytes.Equal(text, []byte(begin)) {
			inBlock = true
		}
		if inBlock {
			if !bytes.HasSuffix(line, []byte("\n")) {
				out.Write(line)
				out.WriteByte('\n')
			} else {
				out.Write(line)
			}
		}
		if bytes.Equal(text, []byte(end)) {
			if !inBlock {
				return nil, fmt.Errorf("end marker without begin")
			}
			return out.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("checklist markers not found")
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
		if _, err := os.Stat(filepath.Join(wd, "docs", "2026-08-16_adoption-and-release-strategy.md")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			t.Fatal("repository root not found")
		}
		wd = parent
	}
}
