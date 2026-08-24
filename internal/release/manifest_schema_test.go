package release_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
	"warptweet.com/warptweet/internal/strictjson"
)

const (
	jsonSchemaDraft202012 = "https://json-schema.org/draft/2020-12/schema"
	digestPlaceholder     = "REPLACE_WITH_64_LOWERCASE_HEXADECIMAL_CHARACTERS"
)

func TestPublishedManifestSchemasConformToRuntimeManifests(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)

	t.Run("client tunnels v1", func(t *testing.T) {
		t.Parallel()

		schema := readPublishedSchema(t, filepath.Join(root, "schemas", "client-tunnels-v1.schema.json"))
		manifest := validClientSchemaConfig()
		if err := config.Validate(manifest); err != nil {
			t.Fatalf("typed client fixture is not runtime-valid: %v", err)
		}
		assertSchemaConformance(t, schema, marshalJSONDocument(t, manifest))

		example := replaceExampleDigests(
			t,
			readFile(t, filepath.Join(root, "examples", "client.example.wt")),
			1,
		)
		if _, err := config.Decode(bytes.NewReader(example)); err != nil {
			t.Fatalf("client example with a concrete digest is not runtime-valid: %v", err)
		}
		assertSchemaConformance(t, schema, decodeJSONDocument(t, example))
	})

	t.Run("server gateway v2", func(t *testing.T) {
		t.Parallel()

		schema := readPublishedSchema(t, filepath.Join(root, "schemas", "server-gateway-v2.schema.json"))
		manifest := validServerSchemaConfig()
		if err := server.Validate(manifest); err != nil {
			t.Fatalf("typed server fixture is not runtime-valid: %v", err)
		}
		assertSchemaConformance(t, schema, marshalJSONDocument(t, manifest))

		example := replaceExampleDigests(
			t,
			readFile(t, filepath.Join(root, "examples", "server.example.wt")),
			2,
		)
		if _, err := server.Decode(bytes.NewReader(example)); err != nil {
			t.Fatalf("server example with concrete digests is not runtime-valid: %v", err)
		}
		assertSchemaConformance(t, schema, decodeJSONDocument(t, example))
	})

	t.Run("server gateway v1 is historical unused", func(t *testing.T) {
		t.Parallel()

		schema := readPublishedSchema(t, filepath.Join(root, "schemas", "server-gateway-v1.schema.json"))
		assertSchemaPropertyConst(t, schema, "schema_version", "1")
		assertSchemaRejection(t, schema, marshalJSONDocument(t, validServerSchemaConfig()))
	})
}

func TestPublishedManifestSchemasDeclareExactClosedContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		kind       string
		version    string
		profileID  string
		identifier string
	}{
		{
			name:       "client tunnels v1",
			path:       "client-tunnels-v1.schema.json",
			kind:       config.ClientTunnelsKind,
			version:    fmt.Sprint(config.CurrentSchemaVersion),
			profileID:  profile.CurrentID,
			identifier: "https://warptweet.com/schemas/client-tunnels-v1.schema.json",
		},
		{
			name:       "server gateway v1 historical",
			path:       "server-gateway-v1.schema.json",
			kind:       server.ManifestKind,
			version:    "1",
			profileID:  profile.CurrentID,
			identifier: "https://warptweet.com/schemas/server-gateway-v1.schema.json",
		},
		{
			name:       "server gateway v2",
			path:       "server-gateway-v2.schema.json",
			kind:       server.ManifestKind,
			version:    fmt.Sprint(server.CurrentSchemaVersion),
			profileID:  profile.CurrentID,
			identifier: "https://warptweet.com/schemas/server-gateway-v2.schema.json",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			schema := readPublishedSchema(
				t,
				filepath.Join(repositoryRoot(t), "schemas", test.path),
			)
			if got := schema["$schema"]; got != jsonSchemaDraft202012 {
				t.Fatalf("$schema = %v, want %q", got, jsonSchemaDraft202012)
			}
			if got := schema["$id"]; got != test.identifier {
				t.Fatalf("$id = %v, want %q", got, test.identifier)
			}
			assertSchemaPropertyConst(t, schema, "kind", test.kind)
			assertSchemaPropertyConst(t, schema, "schema_version", test.version)
			assertSchemaPropertyConst(t, schema, "profile_id", test.profileID)
			assertRuntimeAuthorityComment(t, schema)
			assertClosedRequiredObjects(t, schema, "#")
		})
	}
}

func TestPublishedManifestSchemasRejectUnsafeShapes(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	clientSchema := readPublishedSchema(t, filepath.Join(root, "schemas", "client-tunnels-v1.schema.json"))
	clientDocument := marshalJSONDocument(t, validClientSchemaConfig()).(map[string]any)
	clientTests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "wrong schema version",
			mutate: func(document map[string]any) {
				document["schema_version"] = json.Number("2")
			},
		},
		{
			name: "missing required field",
			mutate: func(document map[string]any) {
				delete(document, "profile_id")
			},
		},
		{
			name: "unknown nested field",
			mutate: func(document map[string]any) {
				document["server"].(map[string]any)["fallback"] = true
			},
		},
		{
			name: "removed private key path",
			mutate: func(document map[string]any) {
				document["private_key_path"] = "keys/client"
			},
		},
		{
			name: "removed SSH binary path",
			mutate: func(document map[string]any) {
				document["ssh_binary_path"] = "/usr/bin/ssh"
			},
		},
		{
			name: "uppercase digest",
			mutate: func(document map[string]any) {
				document["ssh_binary_sha256"] = strings.Repeat("A", 64)
			},
		},
		{
			name: "unsafe user",
			mutate: func(document map[string]any) {
				document["server"].(map[string]any)["user"] = "user;root"
			},
		},
		{
			name: "unsafe tunnel ID",
			mutate: func(document map[string]any) {
				tunnels := document["tunnels"].([]any)
				tunnels[0].(map[string]any)["id"] = "Database/primary"
			},
		},
		{
			name: "broadened listener address",
			mutate: func(document map[string]any) {
				tunnels := document["tunnels"].([]any)
				listen := tunnels[0].(map[string]any)["listen"].(map[string]any)
				listen["address"] = "127.0.0.2"
			},
		},
		{
			name: "port outside bounds",
			mutate: func(document map[string]any) {
				document["server"].(map[string]any)["port"] = json.Number("65536")
			},
		},
	}
	for _, test := range clientTests {
		test := test
		t.Run("client "+test.name, func(t *testing.T) {
			t.Parallel()

			document := cloneJSONDocument(t, clientDocument).(map[string]any)
			test.mutate(document)
			assertSchemaRejection(t, clientSchema, document)
		})
	}

	serverSchema := readPublishedSchema(t, filepath.Join(root, "schemas", "server-gateway-v2.schema.json"))
	serverDocument := marshalJSONDocument(t, validServerSchemaConfig()).(map[string]any)
	serverTests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "wrong schema version",
			mutate: func(document map[string]any) {
				document["schema_version"] = json.Number("1")
			},
		},
		{
			name: "unknown endpoint field",
			mutate: func(document map[string]any) {
				document["target"].(map[string]any)["hostname"] = "database.internal"
			},
		},
		{
			name: "short digest",
			mutate: func(document map[string]any) {
				document["openssh_bundle_manifest_sha256"] = strings.Repeat("b", 63)
			},
		},
		{
			name: "reserved dedicated user",
			mutate: func(document map[string]any) {
				document["dedicated_user"] = "root"
			},
		},
		{
			name: "wrong host key path",
			mutate: func(document map[string]any) {
				document["host_key_path"] = "/tmp/host_key"
			},
		},
		{
			name: "relative authorized keys path",
			mutate: func(document map[string]any) {
				document["authorized_keys_path"] = "authorized_keys/warptweet"
			},
		},
		{
			name: "zero port",
			mutate: func(document map[string]any) {
				document["network"].(map[string]any)["data"].(map[string]any)["listen"].(map[string]any)["port"] = json.Number("0")
			},
		},
		{
			name: "missing network",
			mutate: func(document map[string]any) {
				delete(document, "network")
			},
		},
	}
	for _, test := range serverTests {
		test := test
		t.Run("server "+test.name, func(t *testing.T) {
			t.Parallel()

			document := cloneJSONDocument(t, serverDocument).(map[string]any)
			test.mutate(document)
			assertSchemaRejection(t, serverSchema, document)
		})
	}
}

func validClientSchemaConfig() config.Config {
	return config.Config{
		Kind:            config.ClientTunnelsKind,
		SchemaVersion:   config.CurrentSchemaVersion,
		ProfileID:       profile.CurrentID,
		SSHBinarySHA256: strings.Repeat("a", 64),
		Server: config.Server{
			Address: netip.MustParseAddr("192.0.2.10"),
			Port:    2222,
			User:    server.DefaultDedicatedUser,
		},
		Tunnels: []config.Tunnel{
			{
				ID: "database-primary",
				Listen: config.Endpoint{
					Address: netip.MustParseAddr("127.0.0.1"),
					Port:    15432,
				},
				Target: config.Endpoint{
					Address: netip.MustParseAddr("198.51.100.20"),
					Port:    5432,
				},
			},
		},
		Supervision: config.Supervision{
			InitialBackoff: config.Duration(time.Second),
			MaxBackoff:     config.Duration(30 * time.Second),
		},
	}
}

func validServerSchemaConfig() server.Config {
	return server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            strings.Repeat("a", 64),
		OpenSSHBundleManifestSHA256: strings.Repeat("b", 64),
		Network:                     server.PublicationNetwork(netip.MustParseAddr("192.0.2.10"), 2222, 29722),
		Target: server.Endpoint{
			Address: netip.MustParseAddr("198.51.100.20"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: installlayout.AuthorizedKeysDirectory + "/" + server.DefaultDedicatedUser,
	}
}

func readPublishedSchema(t *testing.T, path string) map[string]any {
	t.Helper()

	document := decodeJSONDocument(t, readFile(t, path))
	schema, ok := document.(map[string]any)
	if !ok {
		t.Fatalf("schema %q has type %T, want object", path, document)
	}
	return schema
}

func replaceExampleDigests(t *testing.T, contents []byte, wantCount int) []byte {
	t.Helper()

	placeholder := []byte(digestPlaceholder)
	if got := bytes.Count(contents, placeholder); got != wantCount {
		t.Fatalf("digest placeholder count = %d, want %d", got, wantCount)
	}
	return bytes.ReplaceAll(contents, placeholder, []byte(strings.Repeat("c", 64)))
}

func marshalJSONDocument(t *testing.T, value any) any {
	t.Helper()

	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	return decodeJSONDocument(t, contents)
}

func cloneJSONDocument(t *testing.T, value any) any {
	t.Helper()
	return marshalJSONDocument(t, value)
}

func decodeJSONDocument(t *testing.T, contents []byte) any {
	t.Helper()

	if err := strictjson.RejectDuplicateObjectNames(contents); err != nil {
		t.Fatalf("JSON document has duplicate object names: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode JSON document: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("JSON document has trailing data: %v", err)
	}
	return document
}

func assertSchemaConformance(t *testing.T, schema map[string]any, document any) {
	t.Helper()
	if err := validatePublishedSchema(schema, schema, document, "$"); err != nil {
		t.Fatalf("document does not conform to published schema: %v", err)
	}
}

func assertSchemaRejection(t *testing.T, schema map[string]any, document any) {
	t.Helper()
	if err := validatePublishedSchema(schema, schema, document, "$"); err == nil {
		t.Fatal("published schema accepted an unsafe document shape")
	}
}

func assertSchemaPropertyConst(t *testing.T, schema map[string]any, property, want string) {
	t.Helper()

	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("schema properties is not an object")
	}
	propertySchema, ok := properties[property].(map[string]any)
	if !ok {
		t.Fatalf("property schema %q is not an object", property)
	}
	if got := fmt.Sprint(propertySchema["const"]); got != want {
		t.Fatalf("%s const = %q, want %q", property, got, want)
	}
}

func assertRuntimeAuthorityComment(t *testing.T, schema map[string]any) {
	t.Helper()

	comment, ok := schema["$comment"].(string)
	if !ok {
		t.Fatal("schema omits root $comment")
	}
	lower := strings.ToLower(comment)
	for _, required := range []string{
		"runtime validation remains authoritative",
		"canonical path",
		"numeric ip",
		"duration",
		"duplicate json object member",
	} {
		if !strings.Contains(lower, required) {
			t.Errorf("root $comment omits %q: %s", required, comment)
		}
	}
}

func assertClosedRequiredObjects(t *testing.T, node any, path string) {
	t.Helper()

	switch value := node.(type) {
	case map[string]any:
		if value["type"] == "object" {
			if additional, exists := value["additionalProperties"]; !exists || additional != false {
				t.Errorf("object schema %s must set additionalProperties to false", path)
			}
			properties, ok := value["properties"].(map[string]any)
			if !ok {
				t.Errorf("object schema %s has no properties object", path)
			} else {
				requiredValues, ok := value["required"].([]any)
				if !ok {
					t.Errorf("object schema %s has no required array", path)
				} else {
					required := make(map[string]struct{}, len(requiredValues))
					for _, item := range requiredValues {
						name, ok := item.(string)
						if !ok {
							t.Errorf("object schema %s has non-string required value %v", path, item)
							continue
						}
						required[name] = struct{}{}
					}
					for name := range properties {
						if _, exists := required[name]; !exists {
							t.Errorf("object schema %s does not require property %q", path, name)
						}
					}
					for name := range required {
						if _, exists := properties[name]; !exists {
							t.Errorf("object schema %s requires undeclared property %q", path, name)
						}
					}
				}
			}
		}
		for name, child := range value {
			assertClosedRequiredObjects(t, child, path+"/"+name)
		}
	case []any:
		for index, child := range value {
			assertClosedRequiredObjects(t, child, fmt.Sprintf("%s/%d", path, index))
		}
	}
}

// validatePublishedSchema implements the audited JSON Schema keyword subset
// used by the two published manifests. It is intentionally test-only: runtime
// manifest decoding and validation remain the product authority.
func validatePublishedSchema(root, schema map[string]any, instance any, path string) error {
	if reference, exists := schema["$ref"]; exists {
		referenceText, ok := reference.(string)
		if !ok {
			return fmt.Errorf("%s: schema $ref is not a string", path)
		}
		referenced, err := resolveLocalSchemaReference(root, referenceText)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := validatePublishedSchema(root, referenced, instance, path); err != nil {
			return err
		}
	}

	if constant, exists := schema["const"]; exists && !reflect.DeepEqual(instance, constant) {
		return fmt.Errorf("%s: value %v does not equal const %v", path, instance, constant)
	}
	if enumValue, exists := schema["enum"]; exists {
		values, ok := enumValue.([]any)
		if !ok {
			return fmt.Errorf("%s: schema enum is not an array", path)
		}
		matched := false
		for _, value := range values {
			if reflect.DeepEqual(instance, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value %v is not in enum", path, instance)
		}
	}
	if notValue, exists := schema["not"]; exists {
		notSchema, ok := notValue.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: schema not value is not an object", path)
		}
		if err := validatePublishedSchema(root, notSchema, instance, path); err == nil {
			return fmt.Errorf("%s: value matches forbidden schema", path)
		}
	}

	typeValue, hasType := schema["type"]
	if !hasType {
		return nil
	}
	typeName, ok := typeValue.(string)
	if !ok {
		return fmt.Errorf("%s: schema type is not a string", path)
	}

	switch typeName {
	case "object":
		object, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: value has type %T, want object", path, instance)
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s: object schema properties is not an object", path)
		}
		if requiredValue, exists := schema["required"]; exists {
			required, ok := requiredValue.([]any)
			if !ok {
				return fmt.Errorf("%s: object schema required is not an array", path)
			}
			for _, item := range required {
				name, ok := item.(string)
				if !ok {
					return fmt.Errorf("%s: object schema required value is not a string", path)
				}
				if _, exists := object[name]; !exists {
					return fmt.Errorf("%s: missing required property %q", path, name)
				}
			}
		}
		for name, value := range object {
			propertyValue, declared := properties[name]
			if !declared {
				if schema["additionalProperties"] == false {
					return fmt.Errorf("%s: additional property %q is forbidden", path, name)
				}
				continue
			}
			propertySchema, ok := propertyValue.(map[string]any)
			if !ok {
				return fmt.Errorf("%s/%s: property schema is not an object", path, name)
			}
			if err := validatePublishedSchema(root, propertySchema, value, path+"/"+name); err != nil {
				return err
			}
		}
	case "array":
		array, ok := instance.([]any)
		if !ok {
			return fmt.Errorf("%s: value has type %T, want array", path, instance)
		}
		if minimumValue, exists := schema["minItems"]; exists {
			minimum, err := schemaInteger(minimumValue)
			if err != nil {
				return fmt.Errorf("%s: invalid minItems: %w", path, err)
			}
			if len(array) < minimum {
				return fmt.Errorf("%s: item count %d is below %d", path, len(array), minimum)
			}
		}
		if itemsValue, exists := schema["items"]; exists {
			itemsSchema, ok := itemsValue.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: array items schema is not an object", path)
			}
			for index, item := range array {
				if err := validatePublishedSchema(root, itemsSchema, item, fmt.Sprintf("%s/%d", path, index)); err != nil {
					return err
				}
			}
		}
	case "string":
		text, ok := instance.(string)
		if !ok {
			return fmt.Errorf("%s: value has type %T, want string", path, instance)
		}
		length := utf8.RuneCountInString(text)
		if minimumValue, exists := schema["minLength"]; exists {
			minimum, err := schemaInteger(minimumValue)
			if err != nil {
				return fmt.Errorf("%s: invalid minLength: %w", path, err)
			}
			if length < minimum {
				return fmt.Errorf("%s: string length %d is below %d", path, length, minimum)
			}
		}
		if maximumValue, exists := schema["maxLength"]; exists {
			maximum, err := schemaInteger(maximumValue)
			if err != nil {
				return fmt.Errorf("%s: invalid maxLength: %w", path, err)
			}
			if length > maximum {
				return fmt.Errorf("%s: string length %d exceeds %d", path, length, maximum)
			}
		}
		if patternValue, exists := schema["pattern"]; exists {
			pattern, ok := patternValue.(string)
			if !ok {
				return fmt.Errorf("%s: schema pattern is not a string", path)
			}
			expression, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("%s: invalid schema pattern %q: %w", path, pattern, err)
			}
			if !expression.MatchString(text) {
				return fmt.Errorf("%s: string does not match pattern %q", path, pattern)
			}
		}
	case "integer":
		number, ok := numericValue(instance)
		if !ok || math.Trunc(number) != number {
			return fmt.Errorf("%s: value %v is not an integer", path, instance)
		}
		if minimumValue, exists := schema["minimum"]; exists {
			minimum, ok := numericValue(minimumValue)
			if !ok {
				return fmt.Errorf("%s: schema minimum is not numeric", path)
			}
			if number < minimum {
				return fmt.Errorf("%s: number %v is below %v", path, number, minimum)
			}
		}
		if maximumValue, exists := schema["maximum"]; exists {
			maximum, ok := numericValue(maximumValue)
			if !ok {
				return fmt.Errorf("%s: schema maximum is not numeric", path)
			}
			if number > maximum {
				return fmt.Errorf("%s: number %v exceeds %v", path, number, maximum)
			}
		}
	default:
		return fmt.Errorf("%s: unsupported test schema type %q", path, typeName)
	}

	return nil
}

func resolveLocalSchemaReference(root map[string]any, reference string) (map[string]any, error) {
	const prefix = "#/$defs/"
	if !strings.HasPrefix(reference, prefix) || len(reference) == len(prefix) {
		return nil, fmt.Errorf("unsupported non-local schema reference %q", reference)
	}
	definitions, ok := root["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema $defs is not an object")
	}
	target, exists := definitions[strings.TrimPrefix(reference, prefix)]
	if !exists {
		return nil, fmt.Errorf("schema reference %q does not exist", reference)
	}
	targetSchema, ok := target.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema reference %q does not identify an object", reference)
	}
	return targetSchema, nil
}

func schemaInteger(value any) (int, error) {
	number, ok := numericValue(value)
	if !ok || math.Trunc(number) != number || number < 0 || number > float64(^uint(0)>>1) {
		return 0, fmt.Errorf("value %v is not a non-negative integer", value)
	}
	return int(number), nil
}

func numericValue(value any) (float64, bool) {
	switch number := value.(type) {
	case json.Number:
		result, err := number.Float64()
		return result, err == nil
	case float64:
		return number, true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint64:
		return float64(number), true
	default:
		return 0, false
	}
}
