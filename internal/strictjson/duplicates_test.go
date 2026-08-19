package strictjson

import (
	"errors"
	"strings"
	"testing"
)

func TestRejectDuplicateObjectNamesAcceptsUniqueNames(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty input delegated to typed decoder": "   ",
		"scalar":                                 `42`,
		"nested values": `{
			"kind":"example",
			"objects":[{"id":1,"data":{"id":2}}, {"id":3}],
			"enabled":true,
			"empty":null
		}`,
		"same name in distinct objects": `[{
			"name":"first"
		},{
			"name":"second"
		}]`,
		"case-sensitive names":               `{"Name":1,"name":2}`,
		"distinct escaped names":             `{"a":1,"\u0062":2}`,
		"trailing value delegated to caller": `{"id":1} {"id":2}`,
	}

	for name, input := range tests {
		name := name
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateObjectNames([]byte(input)); err != nil {
				t.Fatalf("RejectDuplicateObjectNames: %v", err)
			}
		})
	}
}

func TestRejectDuplicateObjectNamesRejectsEveryNestingShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		duplicateName string
	}{
		{
			name:          "top level",
			input:         `{"kind":1,"kind":2}`,
			duplicateName: "kind",
		},
		{
			name:          "nested object",
			input:         `{"server":{"port":22,"port":2222}}`,
			duplicateName: "port",
		},
		{
			name:          "object in array",
			input:         `{"tunnels":[{"id":"one","id":"two"}]}`,
			duplicateName: "id",
		},
		{
			name:          "array in array",
			input:         `[[{"address":"127.0.0.1","address":"127.0.0.2"}]]`,
			duplicateName: "address",
		},
		{
			name:          "empty name",
			input:         `{"":1,"":2}`,
			duplicateName: "",
		},
		{
			name:          "escaped name decodes identically",
			input:         `{"kind":1,"\u006bind":2}`,
			duplicateName: "kind",
		},
		{
			name:          "escaped slash decodes identically",
			input:         `{"a/b":1,"a\/b":2}`,
			duplicateName: "a/b",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := RejectDuplicateObjectNames([]byte(test.input))
			if err == nil {
				t.Fatal("RejectDuplicateObjectNames accepted a duplicate name")
			}
			var duplicateError *DuplicateNameError
			if !errors.As(err, &duplicateError) {
				t.Fatalf("error type = %T, want wrapped *DuplicateNameError: %v", err, err)
			}
			if duplicateError.Name != test.duplicateName {
				t.Fatalf("DuplicateNameError.Name = %q, want %q", duplicateError.Name, test.duplicateName)
			}
			if !strings.Contains(err.Error(), "duplicate JSON object member") {
				t.Fatalf("error %q lacks duplicate-member context", err)
			}
		})
	}
}

func TestRejectDuplicateObjectNamesRejectsMalformedFirstValue(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		`{"kind":`,
		`{"kind":1,}`,
		`[1,2`,
	} {
		if err := RejectDuplicateObjectNames([]byte(input)); err == nil {
			t.Fatalf("RejectDuplicateObjectNames accepted malformed input %q", input)
		}
	}
}

func TestValidateManifestObjectNamesRejectsCaseAndSpellingAmbiguity(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		`{"kind":"client","Kind":"server"}`,
		`{"server":{"address":"192.0.2.10","Address":"192.0.2.11"}}`,
		`{"schema-version":1}`,
		`{"naïve":true}`,
		`{"":true}`,
	} {
		err := ValidateManifestObjectNames([]byte(input))
		if err == nil {
			t.Fatalf("ValidateManifestObjectNames accepted %s", input)
		}
		var nameError *NonCanonicalNameError
		if !errors.As(err, &nameError) {
			t.Fatalf("error type = %T, want *NonCanonicalNameError: %v", err, err)
		}
	}
}

func TestValidateManifestObjectNamesAcceptsCanonicalNestedNames(t *testing.T) {
	t.Parallel()

	input := []byte(`{"schema_version":1,"server":{"address":"192.0.2.10"},"tunnels":[{"id":"one"}]}`)
	if err := ValidateManifestObjectNames(input); err != nil {
		t.Fatalf("ValidateManifestObjectNames: %v", err)
	}
}

func TestRejectDuplicateObjectNamesEnforcesDepthLimit(t *testing.T) {
	t.Parallel()

	nested := func(levels int) []byte {
		return []byte(strings.Repeat("[", levels) + strings.Repeat("]", levels))
	}
	if err := RejectDuplicateObjectNames(nested(32)); err != nil {
		t.Fatalf("32 levels: %v", err)
	}
	if err := RejectDuplicateObjectNames(nested(33)); err == nil {
		t.Fatal("accepted 33 nested levels")
	}
}
