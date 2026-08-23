package enrollment

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDocumentationDoesNotCallInvitesPublicOnly(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	forbidden := []string{"public-only", "Public only", "public only"}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "node_modules" || name == ".cache" || name == "dist" {
				return fs.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".md" && ext != ".go" {
			return nil
		}
		base := filepath.Base(path)
		if base == "2026-08-22_security-reliability-distribution-audit.md" ||
			base == "classification_test.go" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		rel, _ := filepath.Rel(root, path)
		for _, phrase := range forbidden {
			if strings.Contains(text, phrase) && strings.Contains(strings.ToLower(text), "invite") {
				t.Errorf("%s still calls invites %q", rel, phrase)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
