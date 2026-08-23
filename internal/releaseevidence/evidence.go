// Package releaseevidence validates package-to-package release evidence
// documents against the immutable checklist.
package releaseevidence

import (
	"bytes"
	"encoding/json"
	"fmt"

	"warptweet.com/warptweet/internal/strictjson"
)

const (
	// Kind is the release evidence document kind.
	Kind = "warptweet.release-evidence"
	// ChecklistKind is the checklist document kind.
	ChecklistKind = "warptweet.release-evidence-checklist"
)

// Case is one positive or negative evidence requirement.
type Case struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Matrix describes required client/server architecture coverage.
type Matrix struct {
	ClientArtifactProfiles []string `json:"client_artifact_profiles"`
	ServerArtifactProfiles []string `json:"server_artifact_profiles"`
	Note                   string   `json:"note"`
}

// Checklist is the immutable set of required package-interop cases.
type Checklist struct {
	Kind                     string   `json:"kind"`
	SchemaVersion            int      `json:"schema_version"`
	ProfileID                string   `json:"profile_id"`
	RequiresPackageToPackage bool     `json:"requires_package_to_package"`
	ForbidsSourceTreeSubst   bool     `json:"forbids_source_tree_substitution"`
	Positive                 []Case   `json:"positive"`
	Negative                 []Case   `json:"negative"`
	ArtifactBindingFields    []string `json:"artifact_binding_fields"`
	Matrix                   Matrix   `json:"matrix"`
	FileSHA256               string   `json:"-"`
}

// Result is one executed checklist case.
type Result struct {
	ID     string `json:"id"`
	Class  string `json:"class"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func decodeStrict(raw []byte, destination any) error {
	if err := strictjson.RejectDuplicateObjectNames(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("trailing JSON values")
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
