package releasemetadata

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderCaskPinsExactReleaseMetadata(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	templatePath := filepath.Join(root, "homebrew", "Casks", "warptweet.rb.tmpl")
	rendered, err := RenderCask(CaskInput{
		Version:         "1.2.3",
		SHA256ARM64:     strings.Repeat("a", 64),
		GitHubOwnerRepo: "warptweet/warptweet",
		TemplatePath:    templatePath,
	})
	if err != nil {
		t.Fatalf("RenderCask: %v", err)
	}
	for _, required := range []string{
		`version "1.2.3"`,
		`sha256 "` + strings.Repeat("a", 64) + `"`,
		`warptweet-#{version}-darwin-arm64.pkg`,
		`depends_on arch: :arm64`,
		`pkgutil: "com.warptweet.client"`,
		`binary "/Library/Application Support/WarpTweet/bin/warptweet"`,
		`target: "warptweet"`,
		`depends_on macos: ">= :ventura"`,
		`/Library/Application Support/WarpTweet/share/uninstall.sh`,
	} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("rendered cask omits %q\n%s", required, rendered)
		}
	}
	for _, forbidden := range []string{"version :latest", "http://", "{{", "darwin-amd64.pkg", "on_intel"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("rendered cask contains forbidden %q", forbidden)
		}
	}
}

func TestRenderCaskRejectsLatestAndBadDigests(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	templatePath := filepath.Join(root, "homebrew", "Casks", "warptweet.rb.tmpl")
	base := CaskInput{
		Version:         "1.0.0",
		SHA256ARM64:     strings.Repeat("a", 64),
		GitHubOwnerRepo: "warptweet/warptweet",
		TemplatePath:    templatePath,
	}
	badVersion := base
	badVersion.Version = "latest"
	if _, err := RenderCask(badVersion); err == nil {
		t.Fatal("RenderCask accepted latest version")
	}
	badDigest := base
	badDigest.SHA256ARM64 = "nope"
	if _, err := RenderCask(badDigest); err == nil {
		t.Fatal("RenderCask accepted invalid digest")
	}
	badRepo := base
	badRepo.GitHubOwnerRepo = "warptweet/warptweet/extra"
	if _, err := RenderCask(badRepo); err == nil {
		t.Fatal("RenderCask accepted extra repository segment")
	}
}

func TestMacOSPackageScriptsForbidNetworkDownloads(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	for _, relative := range []string{
		"packaging/macos/scripts/preinstall",
		"packaging/macos/scripts/postinstall",
		"packaging/macos/scripts/uninstall.sh",
	} {
		path := filepath.Join(root, relative)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", relative, err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s is not executable", relative)
		}
		contents := string(readFile(t, path))
		for _, forbidden := range []string{
			"curl ",
			"wget ",
			"curl\t",
			"wget\t",
			"http://",
			"https://",
		} {
			if strings.Contains(contents, forbidden) {
				t.Errorf("%s contains forbidden network text %q", relative, forbidden)
			}
		}
	}
}

func TestMacOSPackageBuildScriptContract(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	path := filepath.Join(root, "scripts", "build-macos-pkg.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat build script: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("build-macos-pkg.sh is not executable")
	}
	build := string(readFile(t, path))
	for _, required := range []string{
		`pkgbuild`,
		`productbuild`,
		`WARPTWEET_INSTALLER_IDENTITY`,
		`productsign`,
		`notarytool`,
		`stapler staple`,
		`com.warptweet.client`,
		`warptweet-provisioner`,
		`refusing server helper`,
		`mv -hn --`,
		`WARPTWEET_REQUIRE_SIGNED_PKG`,
		`WARPTWEET_REQUIRE_NOTARIZED_PKG`,
		`TeamIdentifier=$WT_TEAM_ID`,
		`WT_TEAM_ID=CP4268Q8UF`,
	} {
		if !strings.Contains(build, required) {
			t.Errorf("build-macos-pkg.sh omits %q", required)
		}
	}
	for _, forbidden := range []string{
		`curl `,
		`wget `,
		`version :latest`,
	} {
		if strings.Contains(build, forbidden) {
			t.Errorf("build-macos-pkg.sh contains forbidden %q", forbidden)
		}
	}
}

func TestHomebrewCaskTemplateForbidsFloatingVersions(t *testing.T) {
	t.Parallel()

	contents := string(readFile(t, filepath.Join(repositoryRoot(t), "homebrew", "Casks", "warptweet.rb.tmpl")))
	for _, forbidden := range []string{
		"version :latest",
		":latest",
		"http://",
		"darwin-amd64.pkg",
		"on_intel",
		"{{SHA256_AMD64}}",
	} {
		if strings.Contains(contents, forbidden) {
			t.Fatalf("cask template contains forbidden %q", forbidden)
		}
	}
	for _, required := range []string{
		`cask "warptweet"`,
		`pkgutil: "com.warptweet.client"`,
		`binary "/Library/Application Support/WarpTweet/bin/warptweet"`,
		`target: "warptweet"`,
		`depends_on macos: ">= :ventura"`,
		`{{VERSION}}`,
		`{{SHA256_ARM64}}`,
		`depends_on arch: :arm64`,
		`darwin-arm64.pkg`,
	} {
		if !strings.Contains(contents, required) {
			t.Fatalf("cask template omits %q", required)
		}
	}
	if strings.Contains(contents, `launchctl: "com.warptweet.client"`) {
		t.Fatal("cask template references obsolete static client LaunchDaemon")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return contents
}
