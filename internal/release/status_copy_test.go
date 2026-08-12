package release_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestProductCopyForbidsAmbiguousExperimentalBranding(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	forbidden := []string{
		"WarpTweet is experimental",
		"WarpTweet is an experimental",
		"Experimental WarpTweet",
		"experimental WarpTweet",
		"Experimental managed-endpoint",
		"experimental managed-endpoint",
		"Experimental. No supported",
		`"experimental":`,
		`"Experimental"`,
		"Profile.Experimental",
		"Experimental          bool",
		"Experimental bool",
		"> Experimental<",
		">Experimental</",
		"●</span> Experimental",
		"Status | Experimental",
		"| Status | Experimental |",
		"| Experimental | `true` |",
		"Status: experimental",
		"immutable and experimental",
		"profile is immutable and experimental",
		"The product is experimental",
		"experimental fail-closed",
		"experimental security software",
	}

	skipDirs := map[string]struct{}{
		".git":         {},
		".astro":       {},
		"bin":          {},
		"dist":         {},
		"node_modules": {},
	}
	skipFiles := map[string]struct{}{
		// This contract documents the forbidden phrases and the replacement.
		"docs/2026-08-12_homebrew-delivery.md": {},
		// The ban test itself enumerates the forbidden phrases.
		"internal/release/status_copy_test.go": {},
	}
	allowedSuffixes := []string{
		".go", ".md", ".astro", ".ts", ".mjs", ".js", ".json", ".service",
		".yml", ".yaml", ".css", ".html", ".txt", ".env", ".sh",
	}

	var violations []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		if entry.IsDir() {
			if _, skip := skipDirs[name]; skip {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, skip := skipFiles[rel]; skip {
			return nil
		}
		if !hasAnySuffix(rel, allowedSuffixes) {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !utf8.Valid(contents) {
			return nil
		}
		text := string(contents)
		for _, phrase := range forbidden {
			if strings.Contains(text, phrase) {
				violations = append(violations, rel+": "+phrase)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("product-level experimental branding remains:\n%s", strings.Join(violations, "\n"))
	}
}

func hasAnySuffix(path string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
