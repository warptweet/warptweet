package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPublicUsageIsGeneratedFromCommandTable(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	text := stdout.String()
	seen := map[string]int{}
	for _, command := range publicCommands {
		if command.Name == "run" {
			t.Fatal("public command table includes unit-only run")
		}
		if !strings.Contains(text, command.Usage) {
			t.Errorf("usage omits %q", command.Usage)
		}
		seen[command.Name]++
		if seen[command.Name] != 1 {
			t.Errorf("duplicate public command %q", command.Name)
		}
	}
	if strings.Contains(text, "warptweet run ") {
		t.Fatal("usage exposes unit-only run")
	}
}

func TestREADMERenderAuthorizedKeyMatchesUsage(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	readme, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	var usage string
	for _, command := range publicCommands {
		if command.Name == "render-authorized-key" {
			usage = command.Usage
			break
		}
	}
	if usage == "" {
		t.Fatal("missing render-authorized-key usage")
	}
	if !strings.Contains(string(readme), "--not-after") {
		t.Fatal("README omits render-authorized-key --not-after")
	}
}
