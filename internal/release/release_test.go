package release_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/command"
	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/opensshsource"
	"warptweet.com/warptweet/internal/opensslsource"
	"warptweet.com/warptweet/internal/server"
)

func TestPinnedOpenSSHSourceIdentity(t *testing.T) {
	t.Parallel()

	values := readEnvironmentFile(t, filepath.Join(repositoryRoot(t), "third_party", "openssh", "source.env"))
	expected := map[string]string{
		"OPENSSH_VERSION":                 opensshsource.Version,
		"OPENSSH_ARCHIVE":                 opensshsource.Archive,
		"OPENSSH_SOURCE_URL":              opensshsource.SourceURL,
		"OPENSSH_SIGNATURE_URL":           opensshsource.SignatureURL,
		"OPENSSH_RELEASE_KEY_URL":         opensshsource.ReleaseKeyURL,
		"OPENSSH_SOURCE_SHA256":           opensshsource.SourceSHA256,
		"OPENSSH_RELEASE_KEY_FINGERPRINT": opensshsource.ReleaseKeyFingerprint,
	}
	for key, want := range expected {
		if got := values[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if !strings.HasPrefix(values["OPENSSH_SOURCE_URL"], "https://cdn.openbsd.org/") ||
		!strings.HasPrefix(values["OPENSSH_SIGNATURE_URL"], "https://cdn.openbsd.org/") ||
		!strings.HasPrefix(values["OPENSSH_RELEASE_KEY_URL"], "https://cdn.openbsd.org/") {
		t.Fatal("OpenSSH provenance URLs must use the official OpenBSD HTTPS CDN")
	}
}

func TestPinnedOpenSSLSourceIdentity(t *testing.T) {
	t.Parallel()

	values := readEnvironmentFile(t, filepath.Join(repositoryRoot(t), "third_party", "openssl", "source.env"))
	expected := map[string]string{
		"OPENSSL_VERSION":                  opensslsource.Version,
		"OPENSSL_ARCHIVE":                  opensslsource.Archive,
		"OPENSSL_SOURCE_URL":               opensslsource.SourceURL,
		"OPENSSL_SIGNATURE_URL":            opensslsource.SignatureURL,
		"OPENSSL_RELEASE_KEY_URL":          opensslsource.ReleaseKeyURL,
		"OPENSSL_SOURCE_SHA256":            opensslsource.SourceSHA256,
		"OPENSSL_RELEASE_KEY_FINGERPRINT":  opensslsource.ReleaseKeyFingerprint,
		"OPENSSL_LOGICAL_PREFIX":           opensslsource.LogicalPrefix,
		"OPENSSL_LOGICAL_CONFIG_DIRECTORY": opensslsource.LogicalConfigDirectory,
	}
	for key, want := range expected {
		if got := values[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if !strings.HasPrefix(values["OPENSSL_SOURCE_URL"], "https://github.com/openssl/openssl/releases/download/") ||
		!strings.HasPrefix(values["OPENSSL_SIGNATURE_URL"], "https://github.com/openssl/openssl/releases/download/") ||
		values["OPENSSL_RELEASE_KEY_URL"] != "https://openssl-library.org/source/pubkeys.asc" {
		t.Fatal("OpenSSL provenance URLs must use official upstream HTTPS release locations")
	}
}

func TestStaticOpenSSLBuildCIExercisesSupportedArchitectures(t *testing.T) {
	t.Parallel()

	workflow := string(readFile(t, filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml")))
	for _, required := range []string{
		"ubuntu-24.04",
		"ubuntu-24.04-arm",
		"acl",
		"binutils",
		"gpg-agent",
		"libtext-template-perl",
		"perl",
		"sudo",
		"./scripts/provision-openssh-build-account.sh",
		"sudo -u warptweet-build -H env",
		"Allow the OpenSSH build account to read the checkout",
		"chmod -R a+rX",
		"./scripts/fetch-openssl.sh",
		`"$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE"`,
		"readelf -d --wide",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("static OpenSSL CI gate omits %q", required)
		}
	}
}

func TestLinuxGoCIPreparesProductionRuntime(t *testing.T) {
	t.Parallel()

	workflow := string(readFile(t, filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml")))
	for _, required := range []string{
		"Prepare Linux production runtime for unprivileged tests",
		`if: runner.os == 'Linux'`,
		`sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0755 /run/warptweet`,
		`sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0700 /run/warptweet/tunnels`,
		"make check-go",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("Linux Go CI gate omits %q", required)
		}
	}
}

func TestLinuxRCVersionMustMatchCommandConstant(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	source := string(readFile(t, filepath.Join(root, "internal/command/command.go")))
	var extracted []string
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Version") && strings.Contains(line, "=") {
			_, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			value = strings.Trim(value, `"`)
			extracted = append(extracted, value)
		}
	}
	if len(extracted) != 1 {
		t.Fatalf("command.Version bindings = %v", extracted)
	}
	if extracted[0] != command.Version {
		t.Fatalf("parsed Version %q, constant %q", extracted[0], command.Version)
	}
	makefile := string(readFile(t, filepath.Join(root, "Makefile")))
	if !strings.Contains(makefile, "linux-rc:") || !strings.Contains(makefile, "WARPTWEET_VERSION=$(VERSION)") {
		t.Fatal("Makefile omits linux-rc VERSION passthrough")
	}
	script := string(readFile(t, filepath.Join(root, "scripts/build-linux-rc-remote.sh")))
	if !strings.Contains(script, "does not match command.Version") {
		t.Fatal("remote RC script omits command.Version fail-closed check")
	}
}

func TestShellCheckCoversEveryPOSIXScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX scripts are Unix build inputs")
	}

	root := repositoryRoot(t)
	checker := filepath.Join(root, "scripts", "check-shell.sh")
	info, err := os.Stat(checker)
	if err != nil {
		t.Fatalf("stat check-shell.sh: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("check-shell.sh is not executable")
	}

	listed := map[string]struct{}{}
	command := exec.Command(checker, "--list")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("check-shell.sh --list: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		listed[line] = struct{}{}
	}

	discovered := map[string]struct{}{}
	for _, dir := range []string{"scripts", "packaging"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".sh") ||
				path == filepath.Join(root, "packaging", "macos", "scripts", "preinstall") ||
				path == filepath.Join(root, "packaging", "macos", "scripts", "postinstall") {
				discovered[path] = struct{}{}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(discovered) == 0 {
		t.Fatal("no POSIX scripts discovered")
	}
	for path := range discovered {
		if _, ok := listed[path]; !ok {
			t.Errorf("check-shell.sh --list omits %s", path)
		}
	}
	for path := range listed {
		if _, ok := discovered[path]; !ok {
			t.Errorf("check-shell.sh --list includes unexpected %s", path)
		}
	}

	values := readEnvironmentFile(t, filepath.Join(root, "third_party", "shellcheck", "source.env"))
	for _, key := range []string{
		"SHELLCHECK_VERSION",
		"SHELLCHECK_RELEASE_TAG",
		"SHELLCHECK_LINUX_X86_64_SHA256",
		"SHELLCHECK_LINUX_AARCH64_SHA256",
		"SHELLCHECK_DARWIN_X86_64_SHA256",
		"SHELLCHECK_DARWIN_AARCH64_SHA256",
	} {
		if values[key] == "" {
			t.Errorf("shellcheck pin omits %s", key)
		}
	}
	if values["SHELLCHECK_VERSION"] != "0.11.0" || values["SHELLCHECK_RELEASE_TAG"] != "v0.11.0" {
		t.Fatalf("unexpected ShellCheck pin %q / %q", values["SHELLCHECK_VERSION"], values["SHELLCHECK_RELEASE_TAG"])
	}
}

func TestShellCheckClassifiesBashShebangsWithArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX scripts are Unix build inputs")
	}

	root := repositoryRoot(t)
	checker := filepath.Join(root, "scripts", "check-shell.sh")
	dir := t.TempDir()
	cases := []struct {
		shebang string
		want    string
	}{
		{"#!/bin/bash -e", "bash"},
		{"#!/usr/bin/bash -euo pipefail", "bash"},
		{"#!/usr/bin/env bash", "bash"},
		{"#!/usr/bin/env bash -e", "bash"},
		{"#!/usr/bin/env -S bash -e", "bash"},
		{"#!/bin/sh", "sh"},
	}
	for _, test := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(test.shebang, "/", "_"))
		if err := os.WriteFile(path, []byte(test.shebang+"\ntrue\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(checker, "--classify", path)
		command.Dir = root
		output, err := command.Output()
		if err != nil {
			t.Fatalf("classify %q: %v", test.shebang, err)
		}
		if got := strings.TrimSpace(string(output)); got != test.want {
			t.Fatalf("shebang %q dialect=%q, want %q", test.shebang, got, test.want)
		}
	}
}

func TestOpenSSHRegressionBuildAccountPolicyIsDeterministic(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	provisionPath := filepath.Join(root, "scripts", "provision-openssh-build-account.sh")
	provision := string(readFile(t, provisionPath))
	info, err := os.Stat(provisionPath)
	if err != nil {
		t.Fatalf("stat OpenSSH build-account provisioner: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("OpenSSH build-account provisioner is not executable")
	}
	for _, required := range []string{
		`[ "${WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT:-}" != "1" ]`,
		`[ "$(uname -s)" != Linux ]`,
		`[ "$(id -u)" != "0" ]`,
		`WT_BUILD_ACCOUNT=warptweet-build`,
		`WT_BUILD_GROUP=warptweet-build`,
		`WT_BUILD_HOME=/var/lib/warptweet-build`,
		`WT_BUILD_SHELL=/bin/sh`,
		`WT_UNPRIVILEGED_REGRESSION_ACCOUNT=nobody`,
		`--password '*NP*'`,
		`-m 0700`,
		`setfacl -b`,
		`$2 == "*NP*"`,
		`ALL=(root,$WT_UNPRIVILEGED_REGRESSION_ACCOUNT) NOPASSWD: ALL`,
		`sudo -n -u "$WT_UNPRIVILEGED_REGRESSION_ACCOUNT" true`,
	} {
		if !strings.Contains(provision, required) {
			t.Errorf("OpenSSH build-account provisioner omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"/usr/sbin/nologin",
		"set -x",
		`echo "$WT_SHADOW`,
		`printf '%s\n' "$WT_SHADOW`,
	} {
		if strings.Contains(provision, forbidden) {
			t.Errorf("OpenSSH build-account provisioner contains forbidden declaration %q", forbidden)
		}
	}

	build := string(readFile(t, filepath.Join(root, "scripts", "build-openssh.sh")))
	ordered := []string{
		`[ "$(id -u)" = "0" ]`,
		`WT_BUILD_ACCOUNT=warptweet-build`,
		`[ "${SUDO:-}" != "sudo" ]`,
		`[ -n "${TEST_SSH_UNSAFE_PERMISSIONS:-}" ]`,
		`[ "$WT_SHADOW_PASSWORD" = "*NP*" ]`,
		`setfacl -m "u:$WT_UNPRIVILEGED_REGRESSION_ACCOUNT:--x"`,
		`test -x "$WT_OPENSSH_SOURCE_DIRECTORY/ssh-add"`,
		`LC_ALL=C make tests`,
		`restore_regression_acl`,
	}
	previous := -1
	for _, declaration := range ordered {
		relativeIndex := strings.Index(build[previous+1:], declaration)
		if relativeIndex == -1 {
			t.Fatalf("OpenSSH build account policy omits %q", declaration)
		}
		index := previous + 1 + relativeIndex
		previous = index
	}
	for _, required := range []string{
		`source archives and stage must remain inside the private build home`,
		`getfacl -cp "$WT_BUILD_HOME"`,
		`setfacl -b "$WT_ACL_PATH"`,
		`chmod 0700 "$WT_ACL_PATH"`,
		`refusing to restore regression ACLs through a substituted path`,
	} {
		if !strings.Contains(build, required) {
			t.Errorf("OpenSSH build private-account policy omits %q", required)
		}
	}

	workflow := string(readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml")))
	for _, required := range []string{
		`WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1`,
		`sudo -u warptweet-build -H env`,
		`HOME="$WT_BUILD_HOME"`,
		`SUDO=sudo`,
		`/var/lib/warptweet-build/warptweet-openssh-stage`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("CI OpenSSH build-account lane omits %q", required)
		}
	}
	if strings.Contains(workflow, `TEST_SSH_UNSAFE_PERMISSIONS`) {
		t.Fatal("CI bypasses the upstream OpenSSH regression permission checks")
	}
}

func TestOpenSSHBuildAccountProvisionerRejectsMissingOptIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	command := exec.Command("sh", filepath.Join(
		repositoryRoot(t), "scripts", "provision-openssh-build-account.sh",
	))
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=") {
			command.Env = append(command.Env, value)
		}
	}
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("OpenSSH build-account provisioner accepted execution without explicit opt-in")
	}
	if !strings.Contains(string(output), "WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 is required") {
		t.Fatalf("unexpected build-account missing-opt-in error: %s", output)
	}
}

func TestOpenSSHBuildRejectsRootBeforeReadingInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatalf("create fake tool directory: %v", err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "id"), `#!/bin/sh
set -eu
test "$1" = "-u"
printf '%s\n' 0
`)
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh"),
		"/does-not-exist-openssh.tar.gz",
		"/does-not-exist-openssl.tar.gz",
		"/does-not-exist-stage",
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("OpenSSH build accepted root execution")
	}
	if !strings.Contains(string(output), "must run as its dedicated non-root account") {
		t.Fatalf("unexpected root-build refusal: %s", output)
	}
}

func TestLiveTunnelReleaseGateIsDisposableAndFailClosed(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	scriptPath := filepath.Join(root, "scripts", "test-live-tunnel.sh")
	contents := string(readFile(t, scriptPath))
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("stat live tunnel gate: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("live tunnel gate is not executable")
	}
	for _, required := range []string{
		`[ "${WARPTWEET_CI_LIVE_TUNNEL:-}" != "1" ]`,
		`[ "$(uname -s)" != Linux ]`,
		`[ "$(id -u)" != "0" ]`,
		`WT_CONTROLLER=/opt/warptweet/bin/warptweet`,
		`WT_SSH=/opt/warptweet/libexec/openssh/bin/ssh`,
		`WT_SSHD=/opt/warptweet/libexec/openssh/sbin/sshd`,
		`WT_CLIENT_RUNTIME_ROOT=/run/warptweet/tunnels`,
		`WT_CLIENT_USER=warptweet-client`,
		`WT_CLIENT_GROUP=warptweet-client`,
		`WT_CLIENT_MANIFEST=/etc/warptweet/client.wt`,
		`WT_CLIENT_IDENTITY_DIRECTORY=/etc/warptweet/identity`,
		`WT_CLIENT_KEY="$WT_CLIENT_IDENTITY_DIRECTORY/client"`,
		`WT_CLIENT_TRUST_DIRECTORY=/etc/warptweet/trust`,
		`WT_KNOWN_HOSTS="$WT_CLIENT_TRUST_DIRECTORY/known_hosts"`,
		`WT_GLOBAL_KNOWN_HOSTS="$WT_CLIENT_TRUST_DIRECTORY/known_hosts.empty"`,
		`env -i LANG=C LC_ALL=C`,
		`sha256sum --check --strict opt/warptweet/share/openssh-bundle.sha256`,
		`require_public_key_only_account warptweet`,
		`[ "$WT_SHADOW_PASSWORD" != '*NP*' ]`,
		`provision_dedicated_client_account`,
		`groupadd --system --gid 920`,
		`--uid 920`,
		`--gid 920`,
		`dedicated client account or group already exists; refusing to reuse host identity`,
		`--home-dir /nonexistent`,
		`--shell /usr/sbin/nologin`,
		`client UID, primary GID, account name, or group name is not unique`,
		`WT_CLIENT_SUPPLEMENTARY_STATUS=0`,
		`for (member_index = 1; member_index <= count; member_index++)`,
		`END { exit(found ? 0 : 42) }`,
		`' /etc/group || WT_CLIENT_SUPPLEMENTARY_STATUS=$?`,
		`case "$WT_CLIENT_SUPPLEMENTARY_STATUS" in
        0)
            fail "client account is listed as a supplementary group member"
            ;;
        42)
            ;;
        *)
            fail "cannot determine client supplementary group membership"
            ;;
    esac`,
		`[ "$(id -G "$WT_CLIENT_USER")" != "$WT_CLIENT_GID" ]`,
		`install -d -o root -g "$WT_CLIENT_GROUP" -m 0750`,
		`install -o root -g "$WT_CLIENT_GROUP" -m 0440`,
		`install -o "$WT_CLIENT_USER" -g "$WT_CLIENT_GROUP" -m 0600`,
		`"$WT_CLIENT_UID:$WT_CLIENT_GID:600"`,
		`fixed client readiness directory is not service-owned mode 0700`,
		`require_empty_client_runtime_directory`,
		`fixed client readiness directory contains an unexpected persistent entry`,
		`provision_and_probe_tun`,
		`mknod -m 0600 /dev/net/tun c 10 200`,
		`TUNSETIFF capability probe failed`,
		`doctor-server --config "$WT_SERVER_MANIFEST"`,
		`WT_PROFILE=warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20`,
		`"schema_version": 2`,
		`"host": "127.0.0.1"`,
		`prove_managed_client_state_immutable "$WT_CLIENT_USER" service`,
		`prove_managed_client_state_immutable "$WT_SECONDARY_UNPRIVILEGED_USER" secondary`,
		`run_as_dedicated_client "$WT_CONTROLLER" doctor`,
		`client doctor passed as the dedicated non-root client UID`,
		`"$WT_CONTROLLER" run`,
		`controller is not running as the dedicated client UID`,
		`controller SSH child is not running as the dedicated client UID`,
		`"msg":"WarpTweet tunnel authenticated forward ready"`,
		`dump_live_gate_file`,
		`one-shot readiness control socket still exists after authenticated readiness`,
		`authenticated SSH readiness was logged before tunneled payload transit`,
		`WT_RAW_CLIENT_CONFIG="$WT_TEST_CONFIG_DIRECTORY/client-raw.conf"`,
		`raw negative-test config does not use the root-only staging identity`,
		`-o 'RekeyLimit=1K 0'`,
		`grep -Fx 'LogLevel VERBOSE'`,
		`grep -Fx 'LogLevel DEBUG3'`,
		`verify_complete_kex_epochs`,
		`SSH2_MSG_NEWKEYS sent`,
		`SSH2_MSG_NEWKEYS received`,
		`Accepted publickey for warptweet`,
		`WT_COMPOSITE_KEY_SHORT=MLDSA44-ED25519`,
		`finish_epoch(1)`,
		`trailing in-progress rekey`,
		`function proven()`,
		`complete_count`,
		`accept_proof()`,
		`gsub(/\r/`,
		`Later DEBUG3 teardown`,
		`controller carried deterministic HTTP payload`,
		`expect_ssh_failure classical-kex`,
		`WT_CLASSICAL_KEX_CLIENT_CONFIG=`,
		`KexAlgorithms \"curve25519-sha256\"`,
		`ProxyCommand none`,
		`dump_negative_ssh_evidence`,
		`server rejected an offered classical KEX`,
		`expect_ssh_failure wrong-host-pin`,
		`expect_ssh_failure classical-user-key`,
		`signature algorithm $WT_CLASSICAL_KEY_TYPE not in PubkeyAcceptedAlgorithms`,
		`expect_ssh_failure unapproved-target`,
		`expect_session_channel_failure shell-without-command`,
		`expect_session_channel_failure exec-command`,
		`expect_session_channel_failure sftp-subsystem`,
		`expect_session_channel_failure scp-style-exec`,
		`expect_ssh_failure reverse-forward`,
		`expect_ssh_failure tun-forward`,
		`Server has rejected tunnel device forwarding`,
		`raw SOCKS forwarding reached the live unapproved target`,
		`pidfd-signal.py`,
		`server grant-listen`,
		`/run/warptweet/server/grant-session.sock`,
		`install -d -o root -g warptweet-sshd -m 0770 /var/lib/warptweet/sessions`,
		`install -d -o root -g warptweet-sshd -m 2750 /var/lib/warptweet/clients`,
		`"status": "active"`,
		`grant session authority is listening`,
		`independent agent and X11 request evidence remains unproven`,
		`/proc/$1`,
		`BEGIN OPENSSH PRIVATE KEY`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("live tunnel gate omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"rm -rf",
		"killall",
		"pkill",
		"kill -TERM",
		"kill -KILL",
		"systemctl",
		"service warptweet",
		"--runtime-dir",
		`"schema_version": 1`,
		`"ssh_binary_path"`,
		`"private_key_path"`,
		`"known_hosts_path"`,
		`"global_known_hosts_path"`,
		`for (index = 1; index <= count; index++)`,
		"systemd",
		"two-host",
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("live tunnel gate contains unsafe process or filesystem operation %q", forbidden)
		}
	}
	readiness := strings.Index(contents, `"msg":"WarpTweet tunnel authenticated forward ready"`)
	transit := strings.Index(contents, `WT_FORWARD_READY=0`)
	if readiness == -1 || transit == -1 || readiness >= transit {
		t.Fatal("live tunnel gate must require authenticated readiness before payload transit")
	}

	workflow := string(readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml")))
	serverGate := strings.Index(workflow, `./scripts/test-server-preflight.sh`)
	liveGate := strings.Index(workflow, `./scripts/test-live-tunnel.sh`)
	if serverGate == -1 || liveGate == -1 || liveGate <= serverGate {
		t.Fatal("CI must run the live tunnel gate after fixed-layout server preflight")
	}
	for _, required := range []string{
		`WARPTWEET_CI_LIVE_TUNNEL: "1"`,
		`sudo env WARPTWEET_CI_LIVE_TUNNEL="$WARPTWEET_CI_LIVE_TUNNEL"`,
		`passwd`,
		`python3-minimal`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("CI live tunnel gate omits %q", required)
		}
	}

	documentation := string(readFile(t, filepath.Join(
		root,
		"docs",
		"2026-08-10_live-tunnel-gate.md",
	)))
	for _, required := range []string{
		"*NP*",
		"V_10_4_P1/sshd.8",
		"direct-tcpip",
		"cannot identify which listener form created the channel",
		"MaxSessions 0",
		"does not claim independent live agent-forwarding or X11-forwarding rejection evidence",
		"--device /dev/net/tun --cap-add NET_ADMIN",
		"Cleanup signals only through Linux pidfds",
		"Disposal of the CI VM or container is the only filesystem and account cleanup",
	} {
		if !strings.Contains(documentation, required) {
			t.Errorf("live tunnel gate documentation omits %q", required)
		}
	}
}

func TestLiveTunnelReleaseGateRejectsMissingOptIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release script is a Linux CI input")
	}

	scriptPath := filepath.Join(repositoryRoot(t), "scripts", "test-live-tunnel.sh")
	command := exec.Command("sh", scriptPath)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "WARPTWEET_CI_LIVE_TUNNEL=") {
			command.Env = append(command.Env, value)
		}
	}
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("live tunnel gate accepted execution without explicit CI opt-in")
	}
	if !strings.Contains(string(output), "WARPTWEET_CI_LIVE_TUNNEL=1 is required") {
		t.Fatalf("unexpected missing-opt-in error: %s", output)
	}
}

func TestReadinessDocumentationMatchesAnchoredUnlinkBoundary(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	paths := []string{
		filepath.Join(root, "docs", "2026-08-09_architecture.md"),
		filepath.Join(root, "docs", "2026-08-09_threat-model.md"),
		filepath.Join(root, "docs", "2026-08-10_client-readiness.md"),
		filepath.Join(root, "docs", "2026-08-10_client-layout.md"),
	}
	var combined strings.Builder
	for _, path := range paths {
		combined.Write(readFile(t, path))
		combined.WriteByte('\n')
	}
	documentation := combined.String()
	for _, required := range []string{
		"remembers the one-shot control-socket inode",
		"require the exact `ssh -O check` PID to match the foreground child",
		"Remember that socket inode identity",
		"relative to the retained directory descriptor",
		"Close the retained directory descriptor",
		"the child remains alive before Ready",
		"does not send OpenSSH a mux request",
		"does not signal the process",
		"Target health is not checked",
		"WarpTweet never invokes `ssh -O stop` for retirement",
	} {
		if !strings.Contains(documentation, required) {
			t.Errorf("readiness documentation omits %q", required)
		}
	}
	for _, stale := range []string{
		"Execute quiet `ssh -O stop`",
		"The `-O stop` operation retires",
		"stop failure",
		"random, attempt-local OpenSSH control socket",
		"random, one-shot readiness control",
	} {
		if strings.Contains(documentation, stale) {
			t.Errorf("readiness documentation retains stale wording %q", stale)
		}
	}
}

func TestStagedOpenSSHIntegrationDoesNotClaimFixedLayoutClientDoctor(t *testing.T) {
	t.Parallel()

	contents := string(readFile(t, filepath.Join(
		repositoryRoot(t),
		"tests",
		"integration",
		"openssh_test.go",
	)))
	for _, required := range []string{
		`WARPTWEET_OPENSSH_PREFIX`,
		`verifyCompositeSSHSIG`,
		`knownhosts.RenderManagedHost`,
		`engine.RenderClientConfig`,
		`engine.Arguments(clientSpec)`,
		`append([]string{"-G"}, arguments...)`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("staged OpenSSH integration omits %q", required)
		}
	}
	for _, forbidden := range []string{
		`config.Config{`,
		`[]string{"doctor"`,
		`"ssh_binary_path"`,
		`"status":"preflight_ready"`,
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("staged OpenSSH integration still makes fixed-layout client claim %q", forbidden)
		}
	}
}

func TestAuthenticatedFetchScriptsRequireGPGAgent(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"fetch-openssh.sh", "fetch-openssl.sh"} {
		contents := string(readFile(t, filepath.Join(repositoryRoot(t), "scripts", name)))
		if !strings.Contains(contents, "gpg-agent") {
			t.Errorf("%s does not fail closed when gpg-agent is unavailable", name)
		}
	}
}

func TestFixedLayoutServerPreflightScriptIsCIOnlyAndNonListening(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	scriptPath := filepath.Join(root, "scripts", "test-server-preflight.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read fixed-layout preflight script: %v", err)
	}
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("stat fixed-layout preflight script: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("fixed-layout preflight script is not executable")
	}
	contents := string(script)
	required := []string{
		`[ "${WARPTWEET_CI_FIXED_LAYOUT:-}" != "1" ]`,
		`[ "$(uname -s)" != "Linux" ]`,
		`[ "$(id -u)" != "0" ]`,
		`EXPECTED_BUNDLE_MANIFEST_SHA256 EXPECTED_CONTROLLER_SHA256`,
		`realpath -e -- "$WT_SOURCE_STAGE_DIRECTORY"`,
		`realpath -e -- "$WT_SOURCE_CONTROLLER_INPUT"`,
		`for WT_ROOT_DIRECTORY in /opt /etc /var /var/empty /run`,
		`required root directory is not root-owned`,
		`required root directory is world-writable`,
		`install -d -o root -g root -m 0755 /var/empty`,
		`[ -e /opt/warptweet ] || [ -L /opt/warptweet ]`,
		`[ -e /etc/warptweet ] || [ -L /etc/warptweet ]`,
		`bundle manifest does not contain the exact nine fixed files`,
		`does not match the caller-bound digest`,
		`mktemp -d "$WT_SNAPSHOT_PARENT/warptweet-fixed-layout.XXXXXXXXXX"`,
		`cp --no-dereference --reflink=never`,
		`rm -rf -- "$WT_SNAPSHOT_ROOT"`,
		`[ "$WT_CURRENT_SNAPSHOT_ID" != "$WT_SNAPSHOT_ROOT_ID" ]`,
		`installed controller does not match the caller-bound digest`,
		`installed OpenSSH bundle failed authentication before execution`,
		`opt/warptweet/share/openssl-source.txt`,
		`opt/warptweet/share/licenses/openssh/LICENCE`,
		`opt/warptweet/share/licenses/openssl/LICENSE.txt`,
		`"schema_version": 2`,
		`warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20`,
		`--password '*NP*'`,
		`-t mldsa44-ed25519`,
		`render-server`,
		`render-authorized-key`,
		`--not-after "$WT_NOT_AFTER"`,
		`date -u -d '+30 days'`,
		`doctor-server --config "$WT_SERVER_MANIFEST"`,
		`'"status":"preflight_ready"'`,
		`'"role":"server"'`,
	}
	for _, declaration := range required {
		if !strings.Contains(contents, declaration) {
			t.Errorf("fixed-layout preflight script omits %q", declaration)
		}
	}
	for _, forbidden := range []string{
		`rm -rf -- "$WT_SOURCE_STAGE_DIRECTORY"`,
		`rm -rf -- "$WT_STAGE_DIRECTORY"`,
		`rm -rf -- "$WT_CONTROLLER_INPUT"`,
		`rm -rf -- /opt`,
		`rm -rf -- /etc`,
		"systemctl",
		"service warptweet",
		"sshd -D",
		"sshd -d",
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("fixed-layout preflight script contains listener or broad mutation command %q", forbidden)
		}
	}

	firstAccountMutation := strings.Index(contents, "\n    useradd \\\n")
	if firstAccountMutation == -1 {
		t.Fatal("fixed-layout preflight script does not provision its dedicated accounts")
	}
	snapshotVerification := strings.Index(contents, `verify_stage "$WT_STAGE_DIRECTORY"`)
	if snapshotVerification == -1 || snapshotVerification >= firstAccountMutation {
		t.Fatal("root-owned stage snapshot must be verified before account mutation")
	}
	for _, refusal := range []string{
		`[ -e /opt/warptweet ] || [ -L /opt/warptweet ]`,
		`[ -e /etc/warptweet ] || [ -L /etc/warptweet ]`,
		`dedicated test account already exists`,
	} {
		if index := strings.Index(contents, refusal); index == -1 || index >= firstAccountMutation {
			t.Errorf("host-state refusal %q must precede account mutation", refusal)
		}
	}

	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	workflowContents := string(workflow)
	for _, declaration := range []string{
		`WARPTWEET_CI_FIXED_LAYOUT: "1"`,
		`go build -trimpath -o "$WARPTWEET_CONTROLLER" ./cmd/warptweet`,
		`Record FHS ancestor metadata`,
		`stat -c '%n uid=%u gid=%g mode=%a'`,
		`Restore a production /opt ancestor`,
		`sudo chmod 0755 /opt`,
		`test "$WT_OPT_METADATA" = "0:0:755"`,
		`WT_BUNDLE_MANIFEST_SHA256=`,
		`WT_CONTROLLER_SHA256=`,
		`sudo env WARPTWEET_CI_FIXED_LAYOUT="$WARPTWEET_CI_FIXED_LAYOUT"`,
		`./scripts/test-server-preflight.sh`,
		`"$WT_BUNDLE_MANIFEST_SHA256"`,
		`"$WT_CONTROLLER_SHA256"`,
	} {
		if !strings.Contains(workflowContents, declaration) {
			t.Errorf("CI workflow omits fixed-layout gate declaration %q", declaration)
		}
	}
}

func TestFixedLayoutServerPreflightScriptRejectsMissingOptIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release script is a Linux CI input")
	}

	scriptPath := filepath.Join(repositoryRoot(t), "scripts", "test-server-preflight.sh")
	command := exec.Command("sh", scriptPath, "/does-not-exist-stage", "/does-not-exist-controller")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "WARPTWEET_CI_FIXED_LAYOUT=") {
			command.Env = append(command.Env, value)
		}
	}
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("fixed-layout preflight script accepted execution without explicit CI opt-in")
	}
	if !strings.Contains(string(output), "WARPTWEET_CI_FIXED_LAYOUT=1 is required") {
		t.Fatalf("unexpected missing-opt-in error: %s", output)
	}
}

func TestOpenSSHBuildCopiesBothArchivesBeforeHashAndExtraction(t *testing.T) {
	t.Parallel()

	script, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh"))
	if err != nil {
		t.Fatalf("read build script: %v", err)
	}
	contents := string(script)
	ordered := []string{
		`WT_BUILD_ROOT=''`,
		`trap cleanup EXIT`,
		`WT_BUILD_ROOT=$(mktemp -d`,
		`WT_BUILD_ROOT_ID=$(path_identity "$WT_BUILD_ROOT")`,
		`chmod 0700 "$WT_BUILD_ROOT"`,
		`WT_PRIVATE_OPENSSH_ARCHIVE="$WT_BUILD_ROOT/openssh-source-archive.tar.gz"`,
		`WT_PRIVATE_OPENSSL_ARCHIVE="$WT_BUILD_ROOT/openssl-source-archive.tar.gz"`,
		`install -m 0600 "$WT_OPENSSH_ARCHIVE" "$WT_PRIVATE_OPENSSH_ARCHIVE"`,
		`install -m 0600 "$WT_OPENSSL_ARCHIVE" "$WT_PRIVATE_OPENSSL_ARCHIVE"`,
		`sha256sum "$WT_PRIVATE_OPENSSH_ARCHIVE"`,
		`sha256sum "$WT_PRIVATE_OPENSSL_ARCHIVE"`,
		`if [ "$WT_OPENSSH_ACTUAL_SHA256" != "$OPENSSH_SOURCE_SHA256" ]; then`,
		`if [ "$WT_OPENSSL_ACTUAL_SHA256" != "$OPENSSL_SOURCE_SHA256" ]; then`,
		`tar -xzf "$WT_PRIVATE_OPENSSH_ARCHIVE" -C "$WT_OPENSSH_SOURCE_ROOT"`,
		`tar -xzf "$WT_PRIVATE_OPENSSL_ARCHIVE" -C "$WT_OPENSSL_SOURCE_ROOT"`,
		`WT_OPENSSH_SOURCE_DIRECTORY="$WT_OPENSSH_SOURCE_ROOT/openssh-$OPENSSH_VERSION"`,
		`WT_OPENSSL_SOURCE_DIRECTORY="$WT_OPENSSL_SOURCE_ROOT/openssl-$OPENSSL_VERSION"`,
	}
	previous := -1
	for _, declaration := range ordered {
		index := strings.Index(contents, declaration)
		if index == -1 {
			t.Fatalf("build script omits private-archive operation %q", declaration)
		}
		if index <= previous {
			t.Fatalf("private-archive operation %q is out of order", declaration)
		}
		previous = index
	}

	for _, forbidden := range []string{
		`sha256sum "$WT_OPENSSH_ARCHIVE"`,
		`sha256sum "$WT_OPENSSL_ARCHIVE"`,
		`shasum -a 256 "$WT_OPENSSH_ARCHIVE"`,
		`shasum -a 256 "$WT_OPENSSL_ARCHIVE"`,
		`tar -xzf "$WT_OPENSSH_ARCHIVE"`,
		`tar -xzf "$WT_OPENSSL_ARCHIVE"`,
		`rm -rf -- "$WT_FINAL_STAGE_DIRECTORY"`,
		`rm -rf "$WT_FINAL_STAGE_DIRECTORY"`,
		`WT_STAGE_DIRECTORY="$WT_FINAL_STAGE_DIRECTORY"`,
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("build script consumes caller-owned archive after copying: %q", forbidden)
		}
	}
}

func TestOpenSSHReleaseScriptsPublishPrivateDirectoriesWithoutClobbering(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	tests := []struct {
		name      string
		script    string
		required  []string
		forbidden []string
	}{
		{
			name:   "fetch-openssh",
			script: filepath.Join(root, "scripts", "fetch-openssh.sh"),
			required: []string{
				`WT_PRIVATE_ROOT=$(mktemp -d "$WT_DESTINATION_PARENT/.warptweet-openssh-fetch.XXXXXXXX")`,
				`WT_PRIVATE_ROOT_ID=$(path_identity "$WT_PRIVATE_ROOT")`,
				`assert_private_root_unchanged`,
				`WT_PUBLICATION_ID=$(path_identity "$WT_PUBLICATION_DIRECTORY")`,
				`mv -nT -- "$WT_PUBLICATION_DIRECTORY" "$WT_DESTINATION"`,
				`mv -hn -- "$WT_PUBLICATION_DIRECTORY" "$WT_DESTINATION"`,
				`[ "$WT_PUBLISHED_ID" != "$WT_PUBLICATION_ID" ]`,
			},
			forbidden: []string{
				`mkdir -p "$WT_DESTINATION"`,
				`rm -rf -- "$WT_DESTINATION"`,
				`rm -rf "$WT_DESTINATION"`,
				`install -m 0644 "$WT_ARCHIVE_PATH" "$WT_DESTINATION/`,
			},
		},
		{
			name:   "fetch-openssl",
			script: filepath.Join(root, "scripts", "fetch-openssl.sh"),
			required: []string{
				`WT_PRIVATE_ROOT=$(mktemp -d "$WT_DESTINATION_PARENT/.warptweet-openssl-fetch.XXXXXXXX")`,
				`WT_PRIVATE_ROOT_ID=$(path_identity "$WT_PRIVATE_ROOT")`,
				`assert_private_root_unchanged`,
				`WT_PUBLICATION_ID=$(path_identity "$WT_PUBLICATION_DIRECTORY")`,
				`mv -nT -- "$WT_PUBLICATION_DIRECTORY" "$WT_DESTINATION"`,
				`mv -hn -- "$WT_PUBLICATION_DIRECTORY" "$WT_DESTINATION"`,
				`[ "$WT_PUBLISHED_ID" != "$WT_PUBLICATION_ID" ]`,
			},
			forbidden: []string{
				`mkdir -p "$WT_DESTINATION"`,
				`rm -rf -- "$WT_DESTINATION"`,
				`rm -rf "$WT_DESTINATION"`,
				`install -m 0644 "$WT_ARCHIVE_PATH" "$WT_DESTINATION/`,
			},
		},
		{
			name:   "build",
			script: filepath.Join(root, "scripts", "build-openssh.sh"),
			required: []string{
				`WT_BUILD_ROOT=$(mktemp -d "$WT_STAGE_PARENT/.wtb.XXXXXXXX")`,
				`WT_BUILD_ROOT_ID=$(path_identity "$WT_BUILD_ROOT")`,
				`assert_private_build_root_unchanged`,
				`WT_PRIVATE_STAGE_DIRECTORY="$WT_BUILD_ROOT/publish"`,
				`WT_PRIVATE_STAGE_ID=$(path_identity "$WT_PRIVATE_STAGE_DIRECTORY")`,
				`mv -nT -- "$WT_STAGE_DIRECTORY" "$WT_FINAL_STAGE_DIRECTORY"`,
				`mv -hn -- "$WT_STAGE_DIRECTORY" "$WT_FINAL_STAGE_DIRECTORY"`,
				`[ "$WT_PUBLISHED_STAGE_ID" != "$WT_PRIVATE_STAGE_ID" ]`,
			},
			forbidden: []string{
				`mkdir -p "$WT_FINAL_STAGE_DIRECTORY"`,
				`rm -rf -- "$WT_FINAL_STAGE_DIRECTORY"`,
				`rm -rf "$WT_FINAL_STAGE_DIRECTORY"`,
				`WT_STAGE_DIRECTORY="$WT_FINAL_STAGE_DIRECTORY"`,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			contents := string(readFile(t, test.script))
			for _, declaration := range test.required {
				if !strings.Contains(contents, declaration) {
					t.Errorf("release script omits race-safe lifecycle declaration %q", declaration)
				}
			}
			for _, declaration := range test.forbidden {
				if strings.Contains(contents, declaration) {
					t.Errorf("release script recursively deletes or writes directly through a caller path: %q", declaration)
				}
			}
		})
	}
}

func TestOpenSSHBuildBoundsRegressionControlSocketPath(t *testing.T) {
	t.Parallel()

	script := string(readFile(t, filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh")))
	for _, required := range []string{
		"umask 022",
		`WT_BUILD_ROOT=$(mktemp -d "$WT_STAGE_PARENT/.wtb.XXXXXXXX")`,
		`"$WT_STAGE_PARENT"/.wtb.*) ;;`,
		`WT_OPENSSH_SOURCE_ROOT="$WT_BUILD_ROOT/s"`,
		`WT_OPENSSL_SOURCE_ROOT="$WT_BUILD_ROOT/l"`,
		`WT_OPENSSH_REGRESSION_DIRECTORY="$WT_OPENSSH_SOURCE_DIRECTORY/regress"`,
		`[ "${#WT_OPENSSH_REGRESSION_DIRECTORY}" -gt 81 ]`,
		`private OpenSSH regression path exceeds the Linux control-socket budget`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("OpenSSH build omits regression socket-path control %q", required)
		}
	}
	for _, forbidden := range []string{
		`.warptweet-openssh-build.XXXXXXXX`,
		`WT_OPENSSH_SOURCE_ROOT="$WT_BUILD_ROOT/openssh-source"`,
		`WT_OPENSSL_SOURCE_ROOT="$WT_BUILD_ROOT/openssl-source"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("OpenSSH build retains overlong private path component %q", forbidden)
		}
	}
}

func TestOpenSSHBuildHashesAndExtractsPrivateArchiveCopies(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatalf("create fake tool directory: %v", err)
	}
	installFakeOpenSSHBuildAccountTools(t, fakeBin)
	hashLog := filepath.Join(temporaryDirectory, "hash-path")
	tarLog := filepath.Join(temporaryDirectory, "tar-path")
	writeExecutable(t, filepath.Join(fakeBin, "sha256sum"), `#!/bin/sh
set -eu
printf '%s\n' "$1" >> "$WT_TEST_HASH_LOG"
case "${1##*/}" in
	openssh-source-archive.tar.gz)
		test "$(cat "$1")" = "openssh-private-copy-probe"
		WT_DIGEST=$WT_TEST_OPENSSH_HASH
		;;
	openssl-source-archive.tar.gz)
		test "$(cat "$1")" = "openssl-private-copy-probe"
		WT_DIGEST=$WT_TEST_OPENSSL_HASH
		;;
	*)
		exit 90
		;;
esac
printf '%s  %s\n' "$WT_DIGEST" "$1"
`)
	writeExecutable(t, filepath.Join(fakeBin, "tar"), `#!/bin/sh
set -eu
test "$1" = "-xzf"
test "$3" = "-C"
printf '%s\n' "$2" >> "$WT_TEST_TAR_LOG"
case "${2##*/}" in
	openssh-source-archive.tar.gz) exit 0 ;;
	openssl-source-archive.tar.gz) exit 86 ;;
	*) exit 90 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "uname"), `#!/bin/sh
case "${1:-}" in
	-s|'') printf '%s\n' Linux ;;
	-m) printf '%s\n' "${WT_TEST_ARCHITECTURE:-x86_64}" ;;
	*) exit 90 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "readelf"), "#!/bin/sh\nexit 0\n")

	callerOpenSSHArchive := filepath.Join(temporaryDirectory, "caller-openssh.tar.gz")
	callerOpenSSLArchive := filepath.Join(temporaryDirectory, "caller-openssl.tar.gz")
	if err := os.WriteFile(callerOpenSSHArchive, []byte("openssh-private-copy-probe\n"), 0o600); err != nil {
		t.Fatalf("write caller OpenSSH archive probe: %v", err)
	}
	if err := os.WriteFile(callerOpenSSLArchive, []byte("openssl-private-copy-probe\n"), 0o600); err != nil {
		t.Fatalf("write caller OpenSSL archive probe: %v", err)
	}
	stageDirectory := filepath.Join(temporaryDirectory, "stage")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh"),
		callerOpenSSHArchive,
		callerOpenSSLArchive,
		stageDirectory,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TMPDIR="+temporaryDirectory,
		"WT_TEST_OPENSSH_HASH="+opensshsource.SourceSHA256,
		"WT_TEST_OPENSSL_HASH="+opensslsource.SourceSHA256,
		"WT_TEST_HASH_LOG="+hashLog,
		"WT_TEST_TAR_LOG="+tarLog,
	)
	command.Env = append(command.Env, fakeOpenSSHBuildAccountEnvironment(t, temporaryDirectory)...)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("build script unexpectedly continued after the tar probe")
	}

	hashedPaths := nonemptyLines(readFile(t, hashLog))
	extractedPaths := nonemptyLines(readFile(t, tarLog))
	if len(hashedPaths) != 2 || len(extractedPaths) != 2 {
		t.Fatalf("hashed paths = %q; extracted paths = %q; output: %s", hashedPaths, extractedPaths, output)
	}
	for index, hashedPath := range hashedPaths {
		if hashedPath != extractedPaths[index] {
			t.Fatalf("hashed archive %q differs from extracted archive %q: %s", hashedPath, extractedPaths[index], output)
		}
		if hashedPath == callerOpenSSHArchive || hashedPath == callerOpenSSLArchive {
			t.Fatalf("build script consumed a caller-owned archive directly: %s", output)
		}
	}
	if filepath.Base(hashedPaths[0]) != "openssh-source-archive.tar.gz" ||
		filepath.Base(hashedPaths[1]) != "openssl-source-archive.tar.gz" {
		t.Fatalf("private archive paths = %q", hashedPaths)
	}
	physicalTemporaryDirectory, err := filepath.EvalSymlinks(temporaryDirectory)
	if err != nil {
		t.Fatalf("resolve physical test directory: %v", err)
	}
	for _, hashedPath := range hashedPaths {
		relativePath, err := filepath.Rel(physicalTemporaryDirectory, hashedPath)
		if err != nil {
			t.Fatalf("resolve private archive path: %v", err)
		}
		if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			t.Fatalf("private archive escaped the test build root: %q", hashedPath)
		}
		if _, err := os.Stat(hashedPath); !os.IsNotExist(err) {
			t.Fatalf("private build archive was not cleaned up: %v", err)
		}
	}
	if _, err := os.Stat(stageDirectory); !os.IsNotExist(err) {
		t.Fatalf("failed build left a stage directory: %v", err)
	}
}

func TestOpenSSHFetchPublishesVerifiedPrivateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeFetchTools(t, fakeBin, false)
	destination := filepath.Join(temporaryDirectory, "source-cache")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "fetch-openssh.sh"),
		destination,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_EXPECTED_HASH="+opensshsource.SourceSHA256,
		"WT_TEST_FINGERPRINT="+opensshsource.ReleaseKeyFingerprint,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fetch fixture failed: %v: %s", err, output)
	}
	for _, name := range []string{opensshsource.Archive, opensshsource.Archive + ".asc"} {
		if info, err := os.Stat(filepath.Join(destination, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("published fetch file %q is missing or unsafe: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "RELEASE_KEY.asc")); !os.IsNotExist(err) {
		t.Fatalf("fetch destination published an unneeded release-key copy: %v", err)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSHFetchRejectsMismatchedVALIDSIGIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	for _, test := range []struct {
		name        string
		environment string
	}{
		{
			name:        "signer",
			environment: "WT_TEST_SIGNATURE_FINGERPRINT=0000000000000000000000000000000000000000",
		},
		{
			name:        "primary",
			environment: "WT_TEST_SIGNATURE_PRIMARY_FINGERPRINT=0000000000000000000000000000000000000000",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporaryDirectory := t.TempDir()
			fakeBin := filepath.Join(temporaryDirectory, "bin")
			installFakeFetchTools(t, fakeBin, false)
			destination := filepath.Join(temporaryDirectory, "openssh-source-cache")
			command := exec.Command(
				"sh",
				filepath.Join(repositoryRoot(t), "scripts", "fetch-openssh.sh"),
				destination,
			)
			command.Env = append(
				os.Environ(),
				"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"WT_TEST_EXPECTED_HASH="+opensshsource.SourceSHA256,
				"WT_TEST_FINGERPRINT="+opensshsource.ReleaseKeyFingerprint,
				test.environment,
			)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("OpenSSH fetch accepted mismatched VALIDSIG %s identity", test.name)
			}
			if !strings.Contains(string(output), "not made by the pinned primary key") {
				t.Fatalf("unexpected OpenSSH VALIDSIG error: %s", output)
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatalf("failed OpenSSH fetch published a destination: %v", err)
			}
			assertNoPrivateReleaseDirectories(t, temporaryDirectory)
		})
	}
}

func TestOpenSSLFetchPublishesVerifiedPrivateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeFetchTools(t, fakeBin, false)
	destination := filepath.Join(temporaryDirectory, "openssl-source-cache")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "fetch-openssl.sh"),
		destination,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_EXPECTED_HASH="+opensslsource.SourceSHA256,
		"WT_TEST_FINGERPRINT="+opensslsource.ReleaseKeyFingerprint,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL fetch fixture failed: %v: %s", err, output)
	}
	for _, name := range []string{opensslsource.Archive, opensslsource.Archive + ".asc"} {
		if info, err := os.Stat(filepath.Join(destination, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("published OpenSSL fetch file %q is missing or unsafe: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "RELEASE_KEY.asc")); !os.IsNotExist(err) {
		t.Fatalf("OpenSSL fetch destination published an unneeded release-key copy: %v", err)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSLFetchRejectsSignatureFromDifferentPrimaryKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeFetchTools(t, fakeBin, false)
	destination := filepath.Join(temporaryDirectory, "openssl-source-cache")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "fetch-openssl.sh"),
		destination,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_EXPECTED_HASH="+opensslsource.SourceSHA256,
		"WT_TEST_FINGERPRINT="+opensslsource.ReleaseKeyFingerprint,
		"WT_TEST_SIGNATURE_FINGERPRINT=0000000000000000000000000000000000000000",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("OpenSSL fetch accepted a signature from a different primary key")
	}
	if !strings.Contains(string(output), "not made by the pinned primary key") {
		t.Fatalf("unexpected signature-identity error: %s", output)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed OpenSSL fetch published a destination: %v", err)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSLFetchRejectsMismatchedVALIDSIGPrimaryIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeFetchTools(t, fakeBin, false)
	destination := filepath.Join(temporaryDirectory, "openssl-source-cache")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "fetch-openssl.sh"),
		destination,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_EXPECTED_HASH="+opensslsource.SourceSHA256,
		"WT_TEST_FINGERPRINT="+opensslsource.ReleaseKeyFingerprint,
		"WT_TEST_SIGNATURE_PRIMARY_FINGERPRINT=0000000000000000000000000000000000000000",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("OpenSSL fetch accepted a VALIDSIG record with a different primary identity")
	}
	if !strings.Contains(string(output), "not made by the pinned primary key") {
		t.Fatalf("unexpected VALIDSIG primary-identity error: %s", output)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed OpenSSL fetch published a destination: %v", err)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSLFetchRejectsSourceDigestMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeFetchTools(t, fakeBin, false)
	destination := filepath.Join(temporaryDirectory, "openssl-source-cache")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "fetch-openssl.sh"),
		destination,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_EXPECTED_HASH=0000000000000000000000000000000000000000000000000000000000000000",
		"WT_TEST_FINGERPRINT="+opensslsource.ReleaseKeyFingerprint,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("OpenSSL fetch accepted a source archive with the wrong digest")
	}
	if !strings.Contains(string(output), "OpenSSL source SHA-256 mismatch") {
		t.Fatalf("unexpected source-digest error: %s", output)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed OpenSSL fetch published a destination: %v", err)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSHFetchDetectsPublicationTargetAppearanceAndPreservesIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeFetchTools(t, fakeBin, true)
	destination := filepath.Join(temporaryDirectory, "source-cache")
	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "fetch-openssh.sh"),
		destination,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_EXPECTED_HASH="+opensshsource.SourceSHA256,
		"WT_TEST_FINGERPRINT="+opensshsource.ReleaseKeyFingerprint,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("fetch script accepted a destination created during publication")
	}
	if !strings.Contains(string(output), "publication did not consume") {
		t.Fatalf("unexpected fetch publication-substitution error: %s", output)
	}
	if got := strings.TrimSpace(string(readFile(t, filepath.Join(destination, "caller-marker")))); got != "preserve" {
		t.Fatalf("caller target marker = %q, want preserve", got)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSHBuildPublishesCompletePrivateStage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := shortBuildFixtureDirectory(t)
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeBuildTools(t, fakeBin, false)
	callerOpenSSHArchive, callerOpenSSLArchive := writeFakeSourceArchives(t, temporaryDirectory)
	stageDirectory := filepath.Join(temporaryDirectory, "stage")
	command := fakeOpenSSHBuildCommand(t, fakeBin, callerOpenSSHArchive, callerOpenSSLArchive, stageDirectory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build publication fixture failed: %v: %s", err, output)
	}
	for _, relativePath := range []string{
		"opt/warptweet/libexec/openssh/bin/ssh",
		"opt/warptweet/libexec/openssh/sbin/sshd",
		"opt/warptweet/share/openssh-source.txt",
		"opt/warptweet/share/openssl-source.txt",
		"opt/warptweet/share/licenses/openssh/LICENCE",
		"opt/warptweet/share/licenses/openssl/LICENSE.txt",
		"opt/warptweet/share/openssh-bundle.sha256",
		"var/empty/warptweet-sshd",
	} {
		if _, err := os.Stat(filepath.Join(stageDirectory, relativePath)); err != nil {
			t.Fatalf("published build path %q is missing: %v", relativePath, err)
		}
	}
	manifestPaths := manifestPathsFromFixture(t, filepath.Join(
		stageDirectory,
		"opt", "warptweet", "share", "openssh-bundle.sha256",
	))
	wantManifestPaths := []string{
		"opt/warptweet/libexec/openssh/bin/ssh",
		"opt/warptweet/libexec/openssh/bin/ssh-keygen",
		"opt/warptweet/libexec/openssh/libexec/sshd-auth",
		"opt/warptweet/libexec/openssh/libexec/sshd-session",
		"opt/warptweet/libexec/openssh/sbin/sshd",
		"opt/warptweet/share/licenses/openssh/LICENCE",
		"opt/warptweet/share/licenses/openssl/LICENSE.txt",
		"opt/warptweet/share/openssh-source.txt",
		"opt/warptweet/share/openssl-source.txt",
	}
	if strings.Join(manifestPaths, "\n") != strings.Join(wantManifestPaths, "\n") {
		t.Fatalf("bundle manifest paths = %q, want exact nine paths %q", manifestPaths, wantManifestPaths)
	}
	openSSHReceipt := string(readFile(t, filepath.Join(
		stageDirectory,
		"opt", "warptweet", "share", "openssh-source.txt",
	)))
	wantOpenSSHReceipt := strings.Join([]string{
		"receipt_version=1",
		"version=" + opensshsource.Version,
		"engine_version=" + opensshsource.EngineVersion,
		"source_url=" + opensshsource.SourceURL,
		"source_sha256=" + opensshsource.SourceSHA256,
		"release_key_fingerprint=" + opensshsource.ReleaseKeyFingerprint,
		"configure_prefix=/opt/warptweet/libexec/openssh",
		"sysconfdir=/opt/warptweet/etc/openssh",
		"privsep_user=warptweet-sshd",
		"privsep_path=/var/empty/warptweet-sshd",
		"hardening=yes",
		"pie=yes",
		"kerberos5=no",
		"ldns=no",
		"libedit=no",
		"pam=no",
		"selinux=no",
		"zlib=no",
		"sshd_path=/opt/warptweet/libexec/openssh/sbin/sshd",
		"sshd_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"target_tuple=x86_64-pc-linux-gnu",
		"openssl_prefix=" + opensslsource.LogicalPrefix,
		"openssl_source_receipt_path=/opt/warptweet/share/openssl-source.txt",
		"openssl_source_sha256=" + opensslsource.SourceSHA256,
		"openssl_linkage=static",
		"elf_dynamic_policy=passed",
		"tests=passed",
	}, "\n") + "\n"
	if openSSHReceipt != wantOpenSSHReceipt {
		t.Fatalf("OpenSSH receipt = %q, want exact schema %q", openSSHReceipt, wantOpenSSHReceipt)
	}
	openSSLReceipt := string(readFile(t, filepath.Join(
		stageDirectory,
		"opt", "warptweet", "share", "openssl-source.txt",
	)))
	wantOpenSSLReceipt := strings.Join([]string{
		"receipt_version=1",
		"version=" + opensslsource.Version,
		"source_url=" + opensslsource.SourceURL,
		"source_sha256=" + opensslsource.SourceSHA256,
		"release_key_fingerprint=" + opensslsource.ReleaseKeyFingerprint,
		"platform=linux",
		"architecture=x86_64",
		"configure_prefix=" + opensslsource.LogicalPrefix,
		"openssl_config_directory=" + opensslsource.LogicalConfigDirectory,
		"shared=no",
		"module=no",
		"dso=no",
		"pinshared=no",
		"tests=passed",
		"linkage=static",
		"static_libcrypto_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"license_path=/opt/warptweet/share/licenses/openssl/LICENSE.txt",
	}, "\n") + "\n"
	if openSSLReceipt != wantOpenSSLReceipt {
		t.Fatalf("OpenSSL receipt = %q, want exact schema %q", openSSLReceipt, wantOpenSSLReceipt)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSHBuildDetectsPublicationTargetAppearanceAndPreservesIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := shortBuildFixtureDirectory(t)
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeBuildTools(t, fakeBin, true)
	callerOpenSSHArchive, callerOpenSSLArchive := writeFakeSourceArchives(t, temporaryDirectory)
	stageDirectory := filepath.Join(temporaryDirectory, "stage")
	command := fakeOpenSSHBuildCommand(t, fakeBin, callerOpenSSHArchive, callerOpenSSLArchive, stageDirectory)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("build script accepted a stage destination created during publication")
	}
	if !strings.Contains(string(output), "publication did not consume") {
		t.Fatalf("unexpected build publication-substitution error: %s", output)
	}
	if got := strings.TrimSpace(string(readFile(t, filepath.Join(stageDirectory, "caller-marker")))); got != "preserve" {
		t.Fatalf("caller target marker = %q, want preserve", got)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSHBuildRejectsDynamicCryptoAndLoaderPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	for _, test := range []struct {
		name string
		mode string
	}{
		{name: "dynamic-libcrypto", mode: "libcrypto"},
		{name: "dynamic-libssl", mode: "libssl"},
		{name: "rpath", mode: "rpath"},
		{name: "runpath", mode: "runpath"},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporaryDirectory := shortBuildFixtureDirectory(t)
			fakeBin := filepath.Join(temporaryDirectory, "bin")
			installFakeBuildTools(t, fakeBin, false)
			callerOpenSSHArchive, callerOpenSSLArchive := writeFakeSourceArchives(t, temporaryDirectory)
			stageDirectory := filepath.Join(temporaryDirectory, "stage")
			command := fakeOpenSSHBuildCommand(
				t,
				fakeBin,
				callerOpenSSHArchive,
				callerOpenSSLArchive,
				stageDirectory,
			)
			command.Env = append(command.Env, "WT_TEST_READELF_MODE="+test.mode)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("build accepted forbidden readelf mode %q", test.mode)
			}
			if !strings.Contains(string(output), "forbidden crypto dependency or loader path") {
				t.Fatalf("unexpected readelf-policy failure: %s", output)
			}
			if _, err := os.Stat(stageDirectory); !os.IsNotExist(err) {
				t.Fatalf("failed build published a stage directory: %v", err)
			}
			assertNoPrivateReleaseDirectories(t, temporaryDirectory)
		})
	}
}

func TestOpenSSHBuildRejectsUnsupportedLinuxArchitecture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	fakeBin := filepath.Join(temporaryDirectory, "bin")
	installFakeBuildTools(t, fakeBin, false)
	callerOpenSSHArchive, callerOpenSSLArchive := writeFakeSourceArchives(t, temporaryDirectory)
	stageDirectory := filepath.Join(temporaryDirectory, "stage")
	command := fakeOpenSSHBuildCommand(
		t,
		fakeBin,
		callerOpenSSHArchive,
		callerOpenSSLArchive,
		stageDirectory,
	)
	command.Env = append(command.Env, "WT_TEST_ARCHITECTURE=arm64")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("build accepted unsupported Linux architecture arm64")
	}
	if !strings.Contains(string(output), "unsupported Linux production architecture: arm64") {
		t.Fatalf("unexpected architecture-policy failure: %s", output)
	}
	if _, err := os.Stat(stageDirectory); !os.IsNotExist(err) {
		t.Fatalf("architecture refusal published a stage directory: %v", err)
	}
	assertNoPrivateReleaseDirectories(t, temporaryDirectory)
}

func TestOpenSSHReleaseScriptsRejectExistingDestinationsWithoutDeletingThem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release scripts are Linux build inputs")
	}

	temporaryDirectory := t.TempDir()
	markerContents := []byte("caller-owned\n")
	fetchDestination := filepath.Join(temporaryDirectory, "fetch-target")
	buildDestination := filepath.Join(temporaryDirectory, "build-target")
	for _, destination := range []string{fetchDestination, buildDestination} {
		if err := os.Mkdir(destination, 0o700); err != nil {
			t.Fatalf("create existing destination: %v", err)
		}
		if err := os.WriteFile(filepath.Join(destination, "marker"), markerContents, 0o600); err != nil {
			t.Fatalf("write existing-destination marker: %v", err)
		}
	}
	callerArchive := filepath.Join(temporaryDirectory, "caller-source.tar.gz")
	if err := os.WriteFile(callerArchive, []byte("unused\n"), 0o600); err != nil {
		t.Fatalf("write caller archive: %v", err)
	}
	commands := []*exec.Cmd{
		exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "fetch-openssh.sh"), fetchDestination),
		exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh"), callerArchive, callerArchive, buildDestination),
	}
	for index, command := range commands {
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("release script %d accepted an existing destination", index)
		}
		if !strings.Contains(string(output), "must not already exist") {
			t.Fatalf("release script %d returned an unexpected refusal: %s", index, output)
		}
	}
	for _, destination := range []string{fetchDestination, buildDestination} {
		if got := readFile(t, filepath.Join(destination, "marker")); string(got) != string(markerContents) {
			t.Fatalf("existing destination marker changed in %q", destination)
		}
	}
}

func TestOpenSSHStageContainsOnlyRequiredAuthenticatedBundleFiles(t *testing.T) {
	t.Parallel()

	script, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh"))
	if err != nil {
		t.Fatalf("read build script: %v", err)
	}
	contents := string(script)
	for _, required := range []string{
		`install -m 0755 ssh "$WT_INSTALL_PREFIX/bin/ssh"`,
		`install -m 0755 ssh-keygen "$WT_INSTALL_PREFIX/bin/ssh-keygen"`,
		`install -m 0755 sshd "$WT_INSTALL_PREFIX/sbin/sshd"`,
		`install -m 0755 sshd-auth "$WT_INSTALL_PREFIX/libexec/sshd-auth"`,
		`install -m 0755 sshd-session "$WT_INSTALL_PREFIX/libexec/sshd-session"`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("build script omits required allow-listed install %q", required)
		}
	}
	for _, forbidden := range []string{
		`install -m 0755 ssh-keysign`,
		`install -m 0755 sftp-server`,
		`install -m 0755 sftp `,
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("build stage includes forbidden unused executable %q", forbidden)
		}
	}
	for _, required := range []string{
		`LC_ALL=C ./Configure`,
		`"--prefix=$OPENSSL_LOGICAL_PREFIX"`,
		`"--openssldir=$OPENSSL_LOGICAL_CONFIG_DIRECTORY"`,
		`--libdir=lib`,
		`no-shared`,
		`no-module`,
		`no-dso`,
		`no-pinshared`,
		`x86_64|aarch64`,
		`LC_ALL=C make test`,
		`"--with-ssl-dir=$WT_OPENSSL_PREFIX_PHYSICAL"`,
		`--without-rpath`,
		`readelf -d --wide "$WT_EXECUTABLE"`,
		`/\(RPATH\)|\(RUNPATH\)/`,
		`$0 ~ /libcrypto/ || $0 ~ /libssl/`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("static OpenSSL build gate omits %q", required)
		}
	}
	for _, receiptField := range []string{
		`echo "receipt_version=1"`,
		`echo "engine_version=OpenSSH_10.4p1"`,
		`echo "privsep_user=warptweet-sshd"`,
		`echo "privsep_path=/var/empty/warptweet-sshd"`,
		`echo "pam=no"`,
		`echo "zlib=no"`,
		`echo "sshd_sha256=$WT_SSHD_SHA256"`,
		`echo "target_tuple=$WT_TARGET_TUPLE"`,
		`echo "openssl_prefix=$OPENSSL_LOGICAL_PREFIX"`,
		`echo "openssl_source_sha256=$OPENSSL_SOURCE_SHA256"`,
		`echo "openssl_linkage=static"`,
		`echo "elf_dynamic_policy=passed"`,
		`echo "platform=linux"`,
		`echo "architecture=$WT_BUILD_ARCHITECTURE"`,
		`echo "shared=no"`,
		`echo "module=no"`,
		`echo "dso=no"`,
		`echo "pinshared=no"`,
		`echo "linkage=static"`,
		`echo "static_libcrypto_sha256=$WT_OPENSSL_STATIC_CRYPTO_SHA256"`,
		`echo "license_path=/opt/warptweet/share/licenses/openssl/LICENSE.txt"`,
	} {
		if !strings.Contains(contents, receiptField) {
			t.Errorf("build receipt omits required field command %q", receiptField)
		}
	}
	for _, path := range []string{
		"opt/warptweet/share/openssh-source.txt",
		"opt/warptweet/share/openssl-source.txt",
		"opt/warptweet/share/licenses/openssh/LICENCE",
		"opt/warptweet/share/licenses/openssl/LICENSE.txt",
	} {
		if !strings.Contains(contents, path) {
			t.Errorf("bundle manifest does not authenticate %q", path)
		}
	}
}

func TestExampleManifestBoundaries(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	serverExamplePath := filepath.Join(root, "examples", "server.example.wt")
	if _, err := server.Load(serverExamplePath); err == nil {
		t.Fatalf("server example must reject its explicit binary-digest placeholder: %v", err)
	}
	serverExample, err := os.ReadFile(serverExamplePath)
	if err != nil {
		t.Fatalf("read server example: %v", err)
	}
	for _, required := range []string{
		`"schema_version": ` + strconv.Itoa(server.CurrentSchemaVersion),
		`"sshd_binary_sha256"`,
		`"openssh_bundle_manifest_sha256"`,
	} {
		if !strings.Contains(string(serverExample), required) {
			t.Errorf("server example omits required schema declaration %q", required)
		}
	}
	clientExamplePath := filepath.Join(root, "examples", "client.example.wt")
	if _, err := config.Load(clientExamplePath); err == nil {
		t.Fatal("client example must reject its explicit binary-digest placeholder")
	}
	clientExample := string(readFile(t, clientExamplePath))
	if required := `"schema_version": ` + strconv.Itoa(config.CurrentSchemaVersion); !strings.Contains(clientExample, required) {
		t.Errorf("client example omits current schema declaration %q", required)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller did not return the test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func readEnvironmentFile(t *testing.T, path string) map[string]string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open source manifest: %v", err)
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("malformed source manifest line %q", line)
		}
		values[key] = strings.Trim(strings.TrimSpace(value), "'")
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read source manifest: %v", err)
	}
	return values
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return contents
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatalf("write executable %q: %v", path, err)
	}
}

func installFakeOpenSSHBuildAccountTools(t *testing.T, fakeBin string) {
	t.Helper()

	writeExecutable(t, filepath.Join(fakeBin, "id"), `#!/bin/sh
set -eu
case "$1" in
	-u) printf '%s\n' "$WT_TEST_BUILD_UID" ;;
	-g) printf '%s\n' "$WT_TEST_BUILD_GID" ;;
	-un) printf '%s\n' warptweet-build ;;
	-gn|-Gn) printf '%s\n' warptweet-build ;;
	*) exit 90 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "getent"), `#!/bin/sh
set -eu
case "$1:$2" in
	passwd:warptweet-build)
		printf 'warptweet-build:x:%s:%s::%s:/bin/sh\n' \
			"$WT_TEST_BUILD_UID" "$WT_TEST_BUILD_GID" "$WT_TEST_BUILD_HOME"
		;;
	group:warptweet-build)
		printf 'warptweet-build:x:%s:\n' "$WT_TEST_BUILD_GID"
		;;
	passwd:nobody)
		printf 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
		;;
	*) exit 2 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "getfacl"), `#!/bin/sh
set -eu
printf '%s\n' 'user::rwx' 'group::---' 'other::---'
`)
	writeExecutable(t, filepath.Join(fakeBin, "setfacl"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "sudo"), "#!/bin/sh\nexit 0\n")
}

func fakeOpenSSHBuildAccountEnvironment(t *testing.T, home string) []string {
	t.Helper()

	physicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatalf("resolve fake OpenSSH build home: %v", err)
	}
	if err := os.Chmod(physicalHome, 0o700); err != nil {
		t.Fatalf("make fake OpenSSH build home private: %v", err)
	}
	return []string{
		"HOME=" + physicalHome,
		"SUDO=sudo",
		"WT_TEST_BUILD_HOME=" + physicalHome,
		"WT_TEST_BUILD_UID=" + strconv.Itoa(os.Getuid()),
		"WT_TEST_BUILD_GID=" + strconv.Itoa(os.Getgid()),
	}
}

func installFakeFetchTools(t *testing.T, fakeBin string, substituteTarget bool) {
	t.Helper()

	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatalf("create fake fetch tool directory: %v", err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
WT_OUTPUT=''
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--output" ]; then
		WT_OUTPUT=$2
		shift 2
	else
		shift
	fi
done
test -n "$WT_OUTPUT"
printf '%s\n' authenticated-fetch-fixture >"$WT_OUTPUT"
`)
	writeExecutable(t, filepath.Join(fakeBin, "gpg"), `#!/bin/sh
set -eu
for WT_ARGUMENT in "$@"; do
	if [ "$WT_ARGUMENT" = "--show-keys" ]; then
		printf 'fpr:::::::::%s:\n' "$WT_TEST_FINGERPRINT"
		exit 0
	fi
done
for WT_ARGUMENT in "$@"; do
	if [ "$WT_ARGUMENT" = "--status-fd" ]; then
		WT_SIGNER=${WT_TEST_SIGNATURE_FINGERPRINT:-$WT_TEST_FINGERPRINT}
		WT_PRIMARY=${WT_TEST_SIGNATURE_PRIMARY_FINGERPRINT:-$WT_SIGNER}
		printf '[GNUPG:] VALIDSIG %s fixture-fields %s\n' "$WT_SIGNER" "$WT_PRIMARY"
		exit 0
	fi
done
exit 0
`)
	writeExecutable(t, filepath.Join(fakeBin, "gpg-agent"), `#!/bin/sh
set -eu
exit 0
`)
	writeExecutable(t, filepath.Join(fakeBin, "sha256sum"), `#!/bin/sh
set -eu
printf '%s  %s\n' "$WT_TEST_EXPECTED_HASH" "$1"
`)
	if substituteTarget {
		installTargetSubstitutionMove(t, fakeBin)
	}
}

func installFakeBuildTools(t *testing.T, fakeBin string, substituteTarget bool) {
	t.Helper()

	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatalf("create fake build tool directory: %v", err)
	}
	installFakeOpenSSHBuildAccountTools(t, fakeBin)
	writeExecutable(t, filepath.Join(fakeBin, "sha256sum"), `#!/bin/sh
set -eu
case "${1##*/}" in
	openssh-source-archive.tar.gz)
		WT_DIGEST=$WT_TEST_OPENSSH_HASH
		;;
	openssl-source-archive.tar.gz)
		WT_DIGEST=$WT_TEST_OPENSSL_HASH
		;;
	*)
		WT_DIGEST=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
		;;
esac
printf '%s  %s\n' "$WT_DIGEST" "$1"
`)
	writeExecutable(t, filepath.Join(fakeBin, "tar"), `#!/bin/sh
set -eu
test "$1" = "-xzf"
test "$3" = "-C"
case "${2##*/}" in
	openssh-source-archive.tar.gz)
		WT_SOURCE_DIRECTORY="$4/openssh-$WT_TEST_OPENSSH_VERSION"
		mkdir -p "$WT_SOURCE_DIRECTORY"
		printf '%s\n' '#!/bin/sh' 'exit 0' >"$WT_SOURCE_DIRECTORY/configure"
		chmod 0700 "$WT_SOURCE_DIRECTORY/configure"
		printf '%s\n' '#!/bin/sh' 'echo x86_64-pc-linux-gnu' >"$WT_SOURCE_DIRECTORY/config.guess"
		chmod 0700 "$WT_SOURCE_DIRECTORY/config.guess"
		for WT_FILE in ssh ssh-keygen sshd sshd-auth sshd-session; do
			printf '%s\n' "$WT_FILE-fixture" >"$WT_SOURCE_DIRECTORY/$WT_FILE"
			chmod 0700 "$WT_SOURCE_DIRECTORY/$WT_FILE"
		done
		printf '%s\n' 'uidswap.o platform-listen.o $(SKOBJS)' >"$WT_SOURCE_DIRECTORY/Makefile.in"
		printf '%s\n' '#include "srclimit.h"' >"$WT_SOURCE_DIRECTORY/monitor.c"
		printf '%s\n' 'int mm_answer_keyverify(void) {' >>"$WT_SOURCE_DIRECTORY/monitor.c"
		printf '%s\n' '	if (key_blobtype == MM_USERKEY && ret == 0)' >>"$WT_SOURCE_DIRECTORY/monitor.c"
		printf '%s\n' '		auth_activate_options(ssh, key_opts);' >>"$WT_SOURCE_DIRECTORY/monitor.c"
		printf '%s\n' '/* Terminate process */' >>"$WT_SOURCE_DIRECTORY/monitor.c"
		printf '%s\n' '	exit(res);' >>"$WT_SOURCE_DIRECTORY/monitor.c"
		printf '%s\n' '#include "dh.h"' >"$WT_SOURCE_DIRECTORY/sshd-session.c"
		printf '%s\n' '	if (i == 255 && auth_attempted)' >>"$WT_SOURCE_DIRECTORY/sshd-session.c"
		printf '%s\n' licence-fixture >"$WT_SOURCE_DIRECTORY/LICENCE"
		;;
	openssl-source-archive.tar.gz)
		WT_SOURCE_DIRECTORY="$4/openssl-$WT_TEST_OPENSSL_VERSION"
		mkdir -p "$WT_SOURCE_DIRECTORY"
		printf '%s\n' '#!/bin/sh' 'exit 0' >"$WT_SOURCE_DIRECTORY/Configure"
		chmod 0700 "$WT_SOURCE_DIRECTORY/Configure"
		printf '%s\n' openssl-license-fixture >"$WT_SOURCE_DIRECTORY/LICENSE.txt"
		;;
	*)
		exit 90
		;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "make"), `#!/bin/sh
set -eu
for WT_ARGUMENT in "$@"; do
	case "$WT_ARGUMENT" in
		DESTDIR=*)
			WT_DESTDIR=${WT_ARGUMENT#DESTDIR=}
			mkdir -p "$WT_DESTDIR$WT_TEST_OPENSSL_PREFIX/lib"
			printf '%s\n' static-libcrypto-fixture >"$WT_DESTDIR$WT_TEST_OPENSSL_PREFIX/lib/libcrypto.a"
			;;
	esac
done
exit 0
`)
	writeExecutable(t, filepath.Join(fakeBin, "readelf"), `#!/bin/sh
set -eu
case "$1" in
	-h) printf '%s\n' 'ELF Header:' ;;
	-d)
		case "${WT_TEST_READELF_MODE:-allowed}" in
			allowed) printf '%s\n' 'Dynamic section:' ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' ;;
			libcrypto) printf '%s\n' ' 0x0000000000000001 (NEEDED) Shared library: [libcrypto.so.3]' ;;
			libssl) printf '%s\n' ' 0x0000000000000001 (NEEDED) Shared library: [libssl.so.3]' ;;
			rpath) printf '%s\n' ' 0x000000000000000f (RPATH) Library rpath: [/tmp/crypto]' ;;
			runpath) printf '%s\n' ' 0x000000000000001d (RUNPATH) Library runpath: [/tmp/crypto]' ;;
			*) exit 90 ;;
		esac
		;;
	*) exit 90 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "uname"), `#!/bin/sh
set -eu
case "${1:-}" in
	-s|'') printf '%s\n' Linux ;;
	-m) printf '%s\n' "${WT_TEST_ARCHITECTURE:-x86_64}" ;;
	*) exit 90 ;;
esac
`)
	if substituteTarget {
		installTargetSubstitutionMove(t, fakeBin)
	}
}

func installTargetSubstitutionMove(t *testing.T, fakeBin string) {
	t.Helper()

	writeExecutable(t, filepath.Join(fakeBin, "mv"), `#!/bin/sh
set -eu
WT_PENULTIMATE=''
WT_LAST=''
for WT_ARGUMENT in "$@"; do
	WT_PENULTIMATE=$WT_LAST
	WT_LAST=$WT_ARGUMENT
done
test -n "$WT_PENULTIMATE"
test -n "$WT_LAST"
mkdir "$WT_LAST"
printf '%s\n' preserve >"$WT_LAST/caller-marker"
`)
}

func fakeOpenSSHBuildCommand(
	t *testing.T,
	fakeBin string,
	callerOpenSSHArchive string,
	callerOpenSSLArchive string,
	stageDirectory string,
) *exec.Cmd {
	t.Helper()

	command := exec.Command(
		"sh",
		filepath.Join(repositoryRoot(t), "scripts", "build-openssh.sh"),
		callerOpenSSHArchive,
		callerOpenSSLArchive,
		stageDirectory,
	)
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WT_TEST_OPENSSH_HASH="+opensshsource.SourceSHA256,
		"WT_TEST_OPENSSL_HASH="+opensslsource.SourceSHA256,
		"WT_TEST_OPENSSH_VERSION="+opensshsource.Version,
		"WT_TEST_OPENSSL_VERSION="+opensslsource.Version,
		"WT_TEST_OPENSSL_PREFIX="+opensslsource.LogicalPrefix,
	)
	command.Env = append(
		command.Env,
		fakeOpenSSHBuildAccountEnvironment(t, filepath.Dir(callerOpenSSHArchive))...,
	)
	return command
}

func shortBuildFixtureDirectory(t *testing.T) string {
	t.Helper()

	directory, err := os.MkdirTemp("/tmp", "wtb-")
	if err != nil {
		t.Fatalf("create short OpenSSH build fixture directory: %v", err)
	}
	if err := os.Chown(directory, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("normalize short OpenSSH build fixture ownership: %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatalf("inspect short OpenSSH build fixture directory: %v", err)
	}
	t.Cleanup(func() {
		current, statErr := os.Lstat(directory)
		if os.IsNotExist(statErr) {
			return
		}
		if statErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) {
			t.Errorf("refusing cleanup of substituted OpenSSH build fixture directory %q", directory)
			return
		}
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			t.Errorf("remove short OpenSSH build fixture directory: %v", removeErr)
		}
	})
	return directory
}

func writeFakeSourceArchives(t *testing.T, parent string) (string, string) {
	t.Helper()

	openSSHArchive := filepath.Join(parent, "caller-openssh.tar.gz")
	openSSLArchive := filepath.Join(parent, "caller-openssl.tar.gz")
	if err := os.WriteFile(openSSHArchive, []byte("openssh-build-publication-probe\n"), 0o600); err != nil {
		t.Fatalf("write caller OpenSSH archive: %v", err)
	}
	if err := os.WriteFile(openSSLArchive, []byte("openssl-build-publication-probe\n"), 0o600); err != nil {
		t.Fatalf("write caller OpenSSL archive: %v", err)
	}
	return openSSHArchive, openSSLArchive
}

func manifestPathsFromFixture(t *testing.T, path string) []string {
	t.Helper()

	var paths []string
	for _, line := range nonemptyLines(readFile(t, path)) {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed manifest fixture line %q", line)
		}
		paths = append(paths, fields[1])
	}
	return paths
}

func nonemptyLines(contents []byte) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func assertNoPrivateReleaseDirectories(t *testing.T, parent string) {
	t.Helper()

	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("read release parent: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".warptweet-openssh-") ||
			strings.HasPrefix(entry.Name(), ".warptweet-openssl-") {
			t.Errorf("private release directory was not cleaned up: %s", entry.Name())
		}
	}
}
