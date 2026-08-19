// Package strictjson provides security preflights used before typed JSON
// decoding at WarpTweet trust boundaries.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DuplicateNameError reports an object member name that occurred more than
// once in the same JSON object. Name is the decoded name, so equivalent JSON
// escape spellings compare equal.
type DuplicateNameError struct {
	Name string
}

func (e *DuplicateNameError) Error() string {
	return fmt.Sprintf("duplicate JSON object member name %q", e.Name)
}

// NonCanonicalNameError reports an object member name that could be matched
// case-insensitively or interpreted differently by another JSON decoder.
type NonCanonicalNameError struct {
	Name string
}

func (e *NonCanonicalNameError) Error() string {
	return fmt.Sprintf("non-canonical JSON object member name %q", e.Name)
}

// RejectDuplicateObjectNames walks the first JSON value in input and rejects
// duplicate member names at every object nesting depth. Member names are
// compared after JSON string unescaping. Empty input is left to the caller's
// typed decoder, as are type, schema, unknown-field, and trailing-data checks.
func RejectDuplicateObjectNames(input []byte) error {
	return inspectObjectNames(input, false)
}

// ValidateManifestObjectNames rejects duplicates and requires every decoded
// object member name to use lowercase ASCII snake case. This closes the
// case-insensitive struct-field matching behavior of encoding/json.
func ValidateManifestObjectNames(input []byte) error {
	return inspectObjectNames(input, true)
}

const maxJSONDepth = 32

func inspectObjectNames(input []byte, requireCanonical bool) error {
	if len(bytes.TrimSpace(input)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := walkValue(decoder, requireCanonical, 1); err != nil {
		return fmt.Errorf("inspect JSON object members: %w", err)
	}
	return nil
}

func walkValue(decoder *json.Decoder, requireCanonical bool, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		return walkObject(decoder, requireCanonical, depth)
	case '[':
		return walkArray(decoder, requireCanonical, depth)
	default:
		return fmt.Errorf("unexpected opening delimiter %q", delimiter)
	}
}

func walkObject(decoder *json.Decoder, requireCanonical bool, depth int) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("object member name has type %T, want string", token)
		}
		if requireCanonical && !isCanonicalManifestName(name) {
			return &NonCanonicalNameError{Name: name}
		}
		if _, exists := seen[name]; exists {
			return &DuplicateNameError{Name: name}
		}
		seen[name] = struct{}{}
		if err := walkValue(decoder, requireCanonical, depth+1); err != nil {
			return err
		}
	}

	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("object ended with delimiter %q", closing)
	}
	return nil
}

func walkArray(decoder *json.Decoder, requireCanonical bool, depth int) error {
	for decoder.More() {
		if err := walkValue(decoder, requireCanonical, depth+1); err != nil {
			return err
		}
	}

	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(']') {
		return fmt.Errorf("array ended with delimiter %q", closing)
	}
	return nil
}

func isCanonicalManifestName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, value := range []byte(name[1:]) {
		if value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_' {
			continue
		}
		return false
	}
	return true
}
