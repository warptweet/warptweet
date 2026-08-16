// Package releasemetadata renders reviewed release artifacts such as Homebrew
// cask definitions from immutable version and digest inputs.
package releasemetadata

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CaskInput is the exact metadata required to render a pinned Homebrew cask.
type CaskInput struct {
	Version         string
	SHA256ARM64     string
	SHA256AMD64     string
	GitHubOwnerRepo string
	TemplatePath    string
}

// RenderCask substitutes pinned release fields into the cask template.
// It never emits version :latest, branch archives, or floating URLs.
func RenderCask(input CaskInput) (string, error) {
	if err := validateCaskInput(input); err != nil {
		return "", err
	}
	templateBytes, err := os.ReadFile(input.TemplatePath)
	if err != nil {
		return "", fmt.Errorf("read cask template: %w", err)
	}
	rendered := string(templateBytes)
	replacements := map[string]string{
		"{{VERSION}}":           input.Version,
		"{{SHA256_ARM64}}":      strings.ToLower(input.SHA256ARM64),
		"{{SHA256_AMD64}}":      strings.ToLower(input.SHA256AMD64),
		"{{GITHUB_OWNER_REPO}}": input.GitHubOwnerRepo,
	}
	for old, newValue := range replacements {
		if !strings.Contains(rendered, old) {
			return "", fmt.Errorf("cask template missing placeholder %q", old)
		}
		rendered = strings.ReplaceAll(rendered, old, newValue)
	}
	for _, forbidden := range []string{
		"version :latest",
		":latest",
		"http://",
		"{{",
	} {
		if strings.Contains(rendered, forbidden) {
			return "", fmt.Errorf("rendered cask contains forbidden text %q", forbidden)
		}
	}
	if !strings.Contains(rendered, `sha256 "`+strings.ToLower(input.SHA256ARM64)+`"`) ||
		!strings.Contains(rendered, `sha256 "`+strings.ToLower(input.SHA256AMD64)+`"`) ||
		!strings.Contains(rendered, `pkgutil: "com.warptweet.client"`) ||
		!strings.Contains(rendered, `binary "/Library/Application Support/WarpTweet/bin/warptweet"`) ||
		!strings.Contains(rendered, `target: "warptweet"`) ||
		!strings.Contains(rendered, `depends_on macos: ">= :ventura"`) ||
		!strings.Contains(rendered, "darwin-arm64.pkg") ||
		!strings.Contains(rendered, "darwin-amd64.pkg") {
		return "", fmt.Errorf("rendered cask omitted required pinned fields")
	}
	if strings.Contains(rendered, `launchctl: "com.warptweet.client"`) {
		return "", fmt.Errorf("rendered cask references the obsolete static client service")
	}
	return rendered, nil
}

func validateCaskInput(input CaskInput) error {
	if input.Version == "" || strings.Contains(strings.ToLower(input.Version), "latest") {
		return fmt.Errorf("cask version must be an exact non-latest release version")
	}
	if !isLowerHexSHA256(input.SHA256ARM64) || !isLowerHexSHA256(input.SHA256AMD64) {
		return fmt.Errorf("cask digests must be 64 lowercase hex characters")
	}
	if input.GitHubOwnerRepo == "" || strings.Contains(input.GitHubOwnerRepo, " ") {
		return fmt.Errorf("GitHub owner/repo must be non-empty and free of spaces")
	}
	if input.TemplatePath == "" || !filepath.IsAbs(input.TemplatePath) {
		return fmt.Errorf("cask template path must be absolute")
	}
	return nil
}

func isLowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
