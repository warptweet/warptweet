package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinOpenSSHClientBuildScriptContract(t *testing.T) {
	t.Parallel()

	scriptPath := filepath.Join(repositoryRoot(t), "scripts", "build-openssh-darwin.sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("stat darwin build script: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("darwin build script is not executable")
	}
	contents := string(readFile(t, scriptPath))

	ordered := []string{
		`if [ "$(uname -s)" != Darwin ]; then`,
		`arm64|x86_64`,
		`WT_OPENSSL_CONFIGURE_TARGET=darwin64-arm64-cc`,
		`WT_OPENSSL_CONFIGURE_TARGET=darwin64-x86_64-cc`,
		`WT_ARTIFACT_PROFILE_ID=darwin-arm64`,
		`WT_ARTIFACT_PROFILE_ID=darwin-amd64`,
		`export MACOSX_DEPLOYMENT_TARGET=`,
		`WT_BUILD_ROOT=''`,
		`trap cleanup EXIT`,
		`WT_BUILD_ROOT=$(mktemp -d`,
		`install -m 0600 "$WT_OPENSSH_ARCHIVE" "$WT_PRIVATE_OPENSSH_ARCHIVE"`,
		`install -m 0600 "$WT_OPENSSL_ARCHIVE" "$WT_PRIVATE_OPENSSL_ARCHIVE"`,
		`if [ "$WT_OPENSSH_ACTUAL_SHA256" != "$OPENSSH_SOURCE_SHA256" ]; then`,
		`if [ "$WT_OPENSSL_ACTUAL_SHA256" != "$OPENSSL_SOURCE_SHA256" ]; then`,
		`tar -xzf "$WT_PRIVATE_OPENSSH_ARCHIVE" -C "$WT_OPENSSH_SOURCE_ROOT"`,
		`tar -xzf "$WT_PRIVATE_OPENSSL_ARCHIVE" -C "$WT_OPENSSL_SOURCE_ROOT"`,
		`WT_OPENSSH_REGRESSION_DIRECTORY="$WT_OPENSSH_SOURCE_DIRECTORY/regress"`,
		`[ "${#WT_OPENSSH_REGRESSION_DIRECTORY}" -gt 77 ]`,
		`LC_ALL=C ./Configure`,
		`no-shared`,
		`no-module`,
		`no-dso`,
		`no-pinshared`,
		`LC_ALL=C make test`,
		`LC_ALL=C make tests`,
		`install -m 0755 ssh "$WT_INSTALL_PREFIX/bin/ssh"`,
		`install -m 0755 ssh-keygen "$WT_INSTALL_PREFIX/bin/ssh-keygen"`,
		`otool -L "$WT_EXECUTABLE"`,
		`otool -l "$WT_EXECUTABLE"`,
		`$2 == "LC_RPATH"`,
		`OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026`,
		`echo "role=macos-client"`,
		`echo "artifact_profile_id=$WT_ARTIFACT_PROFILE_ID"`,
		`echo "platform=darwin"`,
		`echo "server_helpers=no"`,
		`echo "macho_dynamic_policy=passed"`,
		`echo "static_libcrypto_sha256=$WT_OPENSSL_STATIC_CRYPTO_SHA256"`,
		`mv -hn -- "$WT_STAGE_DIRECTORY" "$WT_FINAL_STAGE_DIRECTORY"`,
	}
	previous := -1
	for _, declaration := range ordered {
		index := strings.Index(contents, declaration)
		if index == -1 {
			t.Fatalf("darwin build script omits %q", declaration)
		}
		if index <= previous {
			t.Fatalf("darwin build script declaration %q is out of order", declaration)
		}
		previous = index
	}
	for _, required := range []string{
		`"--with-ssl-dir=$WT_OPENSSL_PREFIX_PHYSICAL"`,
		`--without-rpath`,
		`mlkem768x25519-sha256`,
		`ssh-mldsa44-ed25519@openssh.com`,
	} {
		if !strings.Contains(contents, required) {
			t.Fatalf("darwin build script omits %q", required)
		}
	}

	for _, forbidden := range []string{
		`install -m 0755 sshd `,
		`install -m 0755 sshd-auth `,
		`install -m 0755 sshd-session `,
		`readelf `,
		`setfacl `,
		`getfacl `,
		`lipo `,
		`version :latest`,
		`rm -rf -- "$WT_FINAL_STAGE_DIRECTORY"`,
		`rm -rf "$WT_FINAL_STAGE_DIRECTORY"`,
		`WT_STAGE_DIRECTORY="$WT_FINAL_STAGE_DIRECTORY"`,
		`sha256sum "$WT_OPENSSH_ARCHIVE"`,
		`shasum -a 256 "$WT_OPENSSH_ARCHIVE"`,
		`tar -xzf "$WT_OPENSSH_ARCHIVE"`,
		`tar -xzf "$WT_OPENSSL_ARCHIVE"`,
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("darwin build script contains forbidden text %q", forbidden)
		}
	}

	for _, path := range []string{
		`Library/Application Support/WarpTweet/libexec/openssh/bin/ssh`,
		`Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen`,
		`Library/Application Support/WarpTweet/share/openssh-source.txt`,
		`Library/Application Support/WarpTweet/share/openssl-source.txt`,
		`Library/Application Support/WarpTweet/share/licenses/openssh/LICENCE`,
		`Library/Application Support/WarpTweet/share/licenses/openssl/LICENSE.txt`,
	} {
		if !strings.Contains(contents, path) {
			t.Errorf("darwin client inventory omits %q", path)
		}
	}
	if !strings.Contains(contents, `share/openssh-bundle.sha256`) {
		t.Error("darwin client inventory omits openssh-bundle.sha256")
	}

	if !strings.Contains(contents, `macOS client bundle manifest must contain exactly six authenticated paths`) {
		t.Fatal("darwin build script does not enforce the six-path client manifest")
	}
}

func TestDarwinOpenSSHClientBuildUsesPinnedSourcesAndNativeOnly(t *testing.T) {
	t.Parallel()

	contents := string(readFile(t, filepath.Join(repositoryRoot(t), "scripts", "build-openssh-darwin.sh")))
	for _, required := range []string{
		`. "$WT_REPOSITORY_ROOT/third_party/openssh/source.env"`,
		`. "$WT_REPOSITORY_ROOT/third_party/openssl/source.env"`,
		`the macOS OpenSSH client build must run as a non-root account`,
		`the macOS OpenSSH client bundle build is supported only on Darwin`,
		`private OpenSSH regression path exceeds the Darwin control-socket budget`,
		`OpenSSH target tuple does not match the native production architecture`,
		`private OpenSSL install unexpectedly produced a shared crypto library or module`,
		`staged OpenSSH executable contains LC_RPATH`,
		`forbidden crypto dependency or non-system load path`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("darwin build script omits native/authenticated gate %q", required)
		}
	}
}

func TestDarwinOpenSSHClientBuildCIExercisesNativeRunners(t *testing.T) {
	t.Parallel()

	workflow := string(readFile(t, filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml")))
	for _, required := range []string{
		"openssh-darwin:",
		"macos-15",
		"macos-14",
		"./scripts/fetch-openssh.sh",
		"./scripts/fetch-openssl.sh",
		"./scripts/build-openssh-darwin.sh",
		"WT_BUILD_HOME=/tmp/wtb",
		"otool -L",
		"otool -l",
		"cmd LC_RPATH",
		"role=macos-client",
		"server_helpers=no",
		"OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026",
		`test "$(wc -l < "$WT_STAGE/$WT_ROOT/share/openssh-bundle.sha256" | tr -d '[:space:]')" = 6`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("darwin OpenSSH CI gate omits %q", required)
		}
	}
	if strings.Contains(workflow, "macos-15-intel") {
		t.Fatal("darwin OpenSSH CI uses an invalid runner label macos-15-intel")
	}
}

func TestDarwinGoBuildsPinVenturaFloor(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	makefile := string(readFile(t, filepath.Join(root, "Makefile")))
	ensure := string(readFile(t, filepath.Join(root, "scripts", "interop", "ensure-artifacts.sh")))
	checker := filepath.Join(root, "scripts", "check-darwin-minos.sh")
	info, err := os.Stat(checker)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("check-darwin-minos.sh is not executable")
	}
	for _, required := range []string{
		"MACOSX_DEPLOYMENT_TARGET ?= 13.0",
		"-mmacosx-version-min=",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile omits %q", required)
		}
	}
	if !strings.Contains(ensure, "MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-13.0}") {
		t.Fatal("ensure-artifacts.sh does not pin the Darwin Go deployment target")
	}
	if !strings.Contains(string(readFile(t, checker)), "minos") {
		t.Fatal("check-darwin-minos.sh does not inspect minos")
	}
}
