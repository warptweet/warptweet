package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONFailuresEmitOneObject(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"host", "--to", "5432", "--stdout", "--json"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode %q: %v", stdout.String(), err)
	}
	if payload["ok"] != false {
		t.Fatalf("payload=%v", payload)
	}
	text := stdout.String()
	for _, forbidden := range []string{`"invite"`, `"mac"`, `"nonce"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("json contains %s: %s", forbidden, text)
		}
	}
}
