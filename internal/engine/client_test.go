package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/profile"
)

func TestRenderClientConfigIsFailClosed(t *testing.T) {
	t.Parallel()

	config, err := RenderClientConfig(validClientSpec(t))
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}

	required := []string{
		`KexAlgorithms "mlkem768x25519-sha256"`,
		`HostKeyAlgorithms "ssh-mldsa44-ed25519@openssh.com"`,
		`PubkeyAcceptedAlgorithms "ssh-mldsa44-ed25519@openssh.com"`,
		`PubkeyAuthentication "yes"`,
		`StrictHostKeyChecking "yes"`,
		`PasswordAuthentication "no"`,
		`SessionType "none"`,
		`ForwardAgent "no"`,
		`ProxyCommand "none"`,
		`ProxyJump "none"`,
		`RekeyLimit "512M" "1h"`,
		`LocalForward "[127.0.0.1]:15432" "[10.0.0.10]:5432"`,
	}
	for _, option := range required {
		if !strings.Contains(config, option) {
			t.Errorf("configuration does not contain %q", option)
		}
	}
	if strings.Contains(config, "+mlkem") || strings.Contains(config, "^mlkem") {
		t.Fatal("configuration appends or prepends algorithms instead of replacing the list")
	}
}

func TestArgumentsExposeOnlyLocalForward(t *testing.T) {
	t.Parallel()

	arguments, err := Arguments(validClientSpec(t))
	if err != nil {
		t.Fatalf("Arguments: %v", err)
	}
	if len(arguments) < 3 || arguments[0] != "-F" || arguments[1] != "none" || arguments[len(arguments)-1] != hostAlias {
		t.Fatalf("arguments do not disable ambient configuration: %q", arguments)
	}
	joined := strings.Join(arguments, " ")
	for _, required := range []string{
		`SessionType=none`,
		`RequestTTY=no`,
		`LocalForward=[127.0.0.1]:15432 [10.0.0.10]:5432`,
		`ControlMaster=no`,
		`ControlPersist=no`,
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("closed arguments do not contain %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "/run/warptweet/client.conf") {
		t.Fatalf("arguments use generated configuration as runtime authority: %s", joined)
	}
	for _, forbidden := range []string{" -R ", " -D ", " -W ", " -A ", " -X "} {
		if strings.Contains(" "+joined+" ", forbidden) {
			t.Fatalf("arguments contain forbidden option %q: %s", forbidden, joined)
		}
	}
}

func TestOrderedClientPolicyDrivesRenderAndArguments(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	policy, err := newClientPolicy(spec, "")
	if err != nil {
		t.Fatalf("newClientPolicy: %v", err)
	}
	config, err := RenderClientConfig(spec)
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	arguments, err := Arguments(spec)
	if err != nil {
		t.Fatalf("Arguments: %v", err)
	}
	if !slices.Equal(arguments[:2], []string{"-F", "none"}) || arguments[len(arguments)-1] != hostAlias {
		t.Fatalf("argument envelope = %q", arguments)
	}
	lines := strings.Split(strings.TrimSuffix(config, "\n"), "\n")
	if len(lines) != len(policy.options)+2 {
		t.Fatalf("rendered lines = %d, want %d", len(lines), len(policy.options)+2)
	}
	for index, option := range policy.options {
		renderedValue := renderConfigTokens(option.values)
		argumentValue := renderArgumentTokens(option.values)
		wantLine := "    " + option.name + " " + renderedValue
		if lines[index+2] != wantLine {
			t.Fatalf("rendered option %d = %q, want %q", index, lines[index+2], wantLine)
		}
		argumentIndex := 2 + index*2
		if arguments[argumentIndex] != "-o" ||
			arguments[argumentIndex+1] != option.name+"="+argumentValue {
			t.Fatalf("argv option %d = %q, want -o %q", index, arguments[argumentIndex:argumentIndex+2], option.name+"="+argumentValue)
		}
	}
}

func TestArgumentsQuotePathsForOpenSSHConfigTokenizer(t *testing.T) {
	t.Parallel()

	arguments, err := Arguments(validClientSpec(t))
	if err != nil {
		t.Fatalf("Arguments: %v", err)
	}
	var sawIdentity bool
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "GSSAPIAuthentication=") {
			t.Fatalf("arguments contain an option unavailable in the pinned no-GSSAPI engine: %q", argument)
		}
		if strings.HasPrefix(argument, "IdentityFile=") {
			sawIdentity = true
			// Linux fixed path has no spaces and stays unquoted; Darwin Application
			// Support paths must be quoted. validClientSpec uses the Linux path.
			if strings.Contains(argument, " ") &&
				(!strings.HasPrefix(argument, `IdentityFile="`) || !strings.HasSuffix(argument, `"`)) {
				t.Fatalf("IdentityFile with spaces must be ssh_config-quoted: %q", argument)
			}
		}
		if strings.HasPrefix(argument, "ProxyJump=") && strings.Contains(argument, `"`) {
			t.Fatalf("ProxyJump none must not be quoted: %q", argument)
		}
	}
	if !sawIdentity {
		t.Fatal("IdentityFile argument missing")
	}

	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bare path without spaces",
			input: "/etc/warptweet/identity/client",
			want:  "/etc/warptweet/identity/client",
		},
		{
			name:  "yes",
			input: "yes",
			want:  "yes",
		},
		{
			name:  "no",
			input: "no",
			want:  "no",
		},
		{
			name:  "none",
			input: "none",
			want:  "none",
		},
		{
			name:  "empty",
			input: "",
			want:  `""`,
		},
		{
			name:  "spaced path",
			input: `/Library/Application Support/WarpTweet/state/identity/client`,
			want:  `"/Library/Application Support/WarpTweet/state/identity/client"`,
		},
		{
			name:  "tab",
			input: "left\tright",
			want:  "\"left\tright\"",
		},
		{
			name:  "backslash",
			input: `path\with\slash`,
			want:  `"path\\with\\slash"`,
		},
		{
			name:  "equals sign",
			input: "name=value",
			want:  `"name=value"`,
		},
		{
			name:  "hash",
			input: "token#comment",
			want:  `"token#comment"`,
		},
		{
			name:  "quote",
			input: `say"hi`,
			want:  `"say\"hi"`,
		},
		{
			name:  "control character",
			input: "a\x01b",
			want:  "\"a\x01b\"",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := quoteArgumentToken(test.input); got != test.want {
				t.Fatalf("quoteArgumentToken(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestRenderRejectsMutatedRegisteredProfile(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	spec.Profile.OpenSSLVersion = "3.5.8"
	if _, err := RenderClientConfig(spec); err == nil {
		t.Fatal("RenderClientConfig accepted a mutated profile")
	}
}

func TestPreflightRejectsHashMismatchBeforeExecution(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte("not an executable"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	dependencies := testClientPreflightDependencies()
	if _, err := preflightWithDependencies(
		context.Background(),
		Binary{Path: path, SHA256: strings.Repeat("0", 64)},
		selected,
		dependencies,
	); err == nil {
		t.Fatal("Preflight accepted the wrong binary hash")
	}
}

func TestPreflightRejectsWritableExecutable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ssh")
	contents := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, contents, 0o722); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o722); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	digest := sha256.Sum256(contents)
	if _, err := preflightWithDependencies(
		context.Background(),
		Binary{Path: path, SHA256: hex.EncodeToString(digest[:])},
		selected,
		testClientPreflightDependencies(),
	); err == nil || !strings.Contains(err.Error(), "group or world writable") {
		t.Fatalf("Preflight error = %v, want writable-executable rejection", err)
	}
}

func TestPreflightAcceptsPinnedCapableEngine(t *testing.T) {
	if testing.Short() {
		t.Skip("uses a local fake executable")
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "ssh")
	script := `#!/bin/sh
[ -z "${LD_PRELOAD:-}" ] || exit 91
[ -z "${OPENSSL_CONF:-}" ] || exit 92
case "$1:$2" in
  -V:) echo 'OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026' >&2 ;;
  -Q:kex) echo 'mlkem768x25519-sha256' ;;
  -Q:key) echo 'ssh-mldsa44-ed25519@openssh.com' ;;
  -Q:sig) echo 'ssh-mldsa44-ed25519@openssh.com' ;;
  -Q:cipher) printf '%s\n' 'chacha20-poly1305@openssh.com' 'aes256-gcm@openssh.com' ;;
  *) exit 64 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	hash := sha256.Sum256([]byte(script))
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	dependencies := productionClientPreflightDependencies()
	dependencies.requireFixedLayout = false
	dependencies.inspector = fixedExecutableInspector{report: executableLinkageReport{
		format:           "ELF",
		openSSLLinkage:   "static",
		dynamicLibraries: []string{"libc.so.6"},
	}}
	dependencies.environment = func() []string {
		return append(os.Environ(), "LD_PRELOAD=/tmp/unsafe.so", "OPENSSL_CONF=/tmp/unsafe.cnf")
	}
	report, err := preflightWithDependencies(
		context.Background(),
		Binary{Path: path, SHA256: hex.EncodeToString(hash[:])},
		selected,
		dependencies,
	)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if report.Profile != profile.CurrentID {
		t.Fatalf("profile = %q, want %q", report.Profile, profile.CurrentID)
	}
	if report.OpenSSLVersion != "3.5.7" || report.OpenSSLVersionText != "OpenSSL 3.5.7 9 Jun 2026" ||
		report.OpenSSLLinkage != "static" || report.ExecutableFormat != "ELF" ||
		!slices.Equal(report.DynamicLibraries, []string{"libc.so.6"}) {
		t.Fatalf("unexpected static OpenSSL evidence: %#v", report)
	}
}

func testClientPreflightDependencies() clientPreflightDependencies {
	return clientPreflightDependencies{
		runner: execClientCommandRunner{},
		inspector: fixedExecutableInspector{report: executableLinkageReport{
			format:           profile.ExecutableFormat,
			openSSLLinkage:   profile.OpenSSLLinkage,
			dynamicLibraries: []string{"libc.so.6"},
		}},
		environment:        os.Environ,
		requireFixedLayout: false,
	}
}

func TestValidateOpenSSHVersionOutputRequiresExactStreams(t *testing.T) {
	t.Parallel()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	exact := []byte("OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026\n")
	tests := []struct {
		name   string
		output clientCommandOutput
		valid  bool
	}{
		{name: "exact stderr", output: clientCommandOutput{stderr: exact}, valid: true},
		{name: "stdout", output: clientCommandOutput{stdout: exact}},
		{name: "missing LF", output: clientCommandOutput{stderr: exact[:len(exact)-1]}},
		{name: "CRLF", output: clientCommandOutput{stderr: append(append([]byte(nil), exact[:len(exact)-1]...), '\r', '\n')}},
		{name: "wrong OpenSSL", output: clientCommandOutput{stderr: []byte("OpenSSH_10.4p1, OpenSSL 3.5.6 7 Apr 2026\n")}},
		{name: "extra line", output: clientCommandOutput{stderr: append(append([]byte(nil), exact...), []byte("wrapper\n")...)}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateOpenSSHVersionOutput(test.output, selected)
			if test.valid && err != nil {
				t.Fatalf("validateOpenSSHVersionOutput: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("validateOpenSSHVersionOutput accepted malformed stream evidence")
			}
		})
	}
}

func validClientSpec(t *testing.T) ClientSpec {
	t.Helper()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return ClientSpec{
		TunnelID:             "database-primary",
		ServerAddress:        netip.MustParseAddr("192.0.2.10"),
		ServerPort:           2222,
		ServerUser:           "warptweet",
		ListenAddress:        netip.MustParseAddr("127.0.0.1"),
		ListenPort:           15432,
		TargetAddress:        netip.MustParseAddr("10.0.0.10"),
		TargetPort:           5432,
		IdentityFile:         "/var/lib/warptweet/identity/client",
		KnownHostsFile:       "/var/lib/warptweet/trust/known_hosts",
		GlobalKnownHostsFile: "/var/lib/warptweet/trust/known_hosts.empty",
		Profile:              selected,
	}
}
