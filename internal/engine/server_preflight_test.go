package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/opensshsource"
	"warptweet.com/warptweet/internal/opensslsource"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestPreflightServerAcceptsAuthenticatedFixedInstallation(t *testing.T) {
	fixture := newServerPreflightFixture(t)

	report, err := preflightServer(
		context.Background(),
		fixture.config,
		fixture.dependencies(),
	)
	if err != nil {
		t.Fatalf("preflightServer: %v", err)
	}
	if report.SSHDPath != installlayout.SSHDPath {
		t.Fatalf("SSHDPath = %q, want %q", report.SSHDPath, installlayout.SSHDPath)
	}
	if report.SSHDBinarySHA256 != fixture.config.SSHDBinarySHA256 {
		t.Fatalf("SSHDBinarySHA256 = %q, want %q", report.SSHDBinarySHA256, fixture.config.SSHDBinarySHA256)
	}
	if report.OpenSSHBundleManifestSHA256 != fixture.config.OpenSSHBundleManifestSHA256 {
		t.Fatalf(
			"OpenSSHBundleManifestSHA256 = %q, want %q",
			report.OpenSSHBundleManifestSHA256,
			fixture.config.OpenSSHBundleManifestSHA256,
		)
	}
	if report.EngineVersion != opensshsource.EngineVersion {
		t.Fatalf("EngineVersion = %q, want %q", report.EngineVersion, opensshsource.EngineVersion)
	}
	if report.Profile != profile.CurrentID {
		t.Fatalf("Profile = %q, want %q", report.Profile, profile.CurrentID)
	}
	if report.OpenSSLVersion != profile.OpenSSLVersion ||
		report.OpenSSLVersionText != profile.OpenSSLVersionText ||
		report.OpenSSLLinkage != profile.OpenSSLLinkage ||
		report.ExecutableFormat != profile.ExecutableFormat ||
		report.StaticLibcryptoSHA256 != strings.Repeat("d", 64) {
		t.Fatalf("unexpected server OpenSSL evidence: %#v", report)
	}
	wantHostDigest := sha256.Sum256(fixture.hostPublicKey)
	if report.HostPublicKeySHA256 != hex.EncodeToString(wantHostDigest[:]) {
		t.Fatalf(
			"HostPublicKeySHA256 = %q, want %q",
			report.HostPublicKeySHA256,
			hex.EncodeToString(wantHostDigest[:]),
		)
	}
	if report.AuthorizedKeyCount != 1 {
		t.Fatalf("AuthorizedKeyCount = %d, want 1", report.AuthorizedKeyCount)
	}
	if got, want := fixture.runner.calls, 4; got != want {
		t.Fatalf("runner calls = %d, want %d", got, want)
	}
	if got, want := fixture.inspector.calls, 10; got != want {
		t.Fatalf("executable inspector calls = %d, want %d", got, want)
	}
	for _, executablePath := range []string{
		fixture.layout.sshPath,
		fixture.layout.sshKeygenPath,
		fixture.layout.sshdPath,
		fixture.layout.sshdAuthPath,
		fixture.layout.sshdSessionPath,
	} {
		if got := fixture.inspector.paths[executablePath]; got != 2 {
			t.Errorf("inspector calls for %q = %d, want 2", executablePath, got)
		}
	}
	wantEnvironment := []string{"LANG=C", "LC_ALL=C"}
	for index, environment := range fixture.runner.environments {
		if !slices.Equal(environment, wantEnvironment) {
			t.Errorf("runner environment %d = %q, want %q", index, environment, wantEnvironment)
		}
	}
	if got, want := fixture.accounts.calls, 2; got != want {
		t.Fatalf("account inspector calls = %d, want %d", got, want)
	}
	if got, want := fixture.privsepOwnerCalls, 4; got != want {
		t.Fatalf("privilege-separation owner validator calls = %d, want %d", got, want)
	}
}

func TestValidateDerivedHostPublicKeyNormalizesOpenSSHComment(t *testing.T) {
	t.Parallel()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	encoded := serverTestPublicKeyBlob(selected, 0x42)
	want := []byte(selected.AuthenticationKeyType + " " + encoded + "\n")
	for _, output := range [][]byte{
		want,
		[]byte(selected.AuthenticationKeyType + " " + encoded + " warptweet-ci-host\n"),
		[]byte(selected.AuthenticationKeyType + " " + encoded + " managed host identity\n"),
	} {
		got, validateErr := validateDerivedHostPublicKey(
			serverCommandResult{stdout: output},
			selected,
		)
		if validateErr != nil {
			t.Fatalf("validateDerivedHostPublicKey: %v", validateErr)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("normalized public key differs from comment-free identity")
		}
	}
}

func TestPreflightServerHostIdentityDigestIgnoresOpenSSHComment(t *testing.T) {
	t.Parallel()

	fixture := newServerPreflightFixture(t)
	commented := append(
		append([]byte(nil), bytes.TrimSuffix(fixture.hostPublicKey, []byte{'\n'})...),
		[]byte(" warptweet-ci-host\n")...,
	)
	fixture.runner.hostPublicKey = commented

	report, err := preflightServer(
		context.Background(),
		fixture.config,
		fixture.dependencies(),
	)
	if err != nil {
		t.Fatalf("preflightServer: %v", err)
	}
	wantDigest := sha256.Sum256(fixture.hostPublicKey)
	if report.HostPublicKeySHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf(
			"HostPublicKeySHA256 = %q, want comment-free %q",
			report.HostPublicKeySHA256,
			hex.EncodeToString(wantDigest[:]),
		)
	}
}

func TestValidateDerivedHostPublicKeyRejectsAmbiguousComment(t *testing.T) {
	t.Parallel()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	encoded := serverTestPublicKeyBlob(selected, 0x42)
	for _, output := range [][]byte{
		[]byte(selected.AuthenticationKeyType + " " + encoded + " \n"),
		[]byte(selected.AuthenticationKeyType + "  " + encoded + "\n"),
		[]byte(selected.AuthenticationKeyType + " " + encoded + " unsafe\tcomment\n"),
	} {
		if _, validateErr := validateDerivedHostPublicKey(
			serverCommandResult{stdout: output},
			selected,
		); validateErr == nil {
			t.Fatalf("validateDerivedHostPublicKey accepted ambiguous output shape")
		}
	}
}

func TestPreflightServerRejectsAttestationAndPolicySubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *serverPreflightFixture)
		want   string
	}{
		{
			name: "unsafe fixed-path ancestor mode",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				if err := os.Chmod(filepath.Dir(fixture.layout.sshdPath), 0o770); err != nil {
					t.Fatalf("chmod fixed-path ancestor: %v", err)
				}
			},
			want: "fixed-path ancestor",
		},
		{
			name: "symlinked fixed-path ancestor",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				directory := filepath.Dir(fixture.layout.sshKeygenPath)
				realDirectory := directory + ".real"
				if err := os.Rename(directory, realDirectory); err != nil {
					t.Fatalf("rename fixed-path ancestor: %v", err)
				}
				if err := os.Symlink(realDirectory, directory); err != nil {
					t.Fatalf("symlink fixed-path ancestor: %v", err)
				}
			},
			want: "fixed-path ancestor",
		},
		{
			name: "unsafe privilege-separation jail mode",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				if err := os.Chmod(fixture.layout.privsepDirectory, 0o700); err != nil {
					t.Fatalf("chmod privilege-separation jail: %v", err)
				}
			},
			want: "want 0755",
		},
		{
			name: "unsafe privilege-separation jail owner",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.privsepOwnerErr = errors.New("must be owned by root:root")
			},
			want: "root:root",
		},
		{
			name: "invalid Unix account contract",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.accounts.err = errors.New("unsafe account reuse")
			},
			want: "Unix account contract",
		},
		{
			name: "direct sshd digest",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.config.SSHDBinarySHA256 = strings.Repeat("0", 64)
			},
			want: "sshd SHA-256",
		},
		{
			name: "bundle manifest digest",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.config.OpenSSHBundleManifestSHA256 = strings.Repeat("0", 64)
			},
			want: "bundle manifest SHA-256",
		},
		{
			name: "helper binary hash",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				writeServerTestFile(t, fixture.layout.sshdAuthPath, []byte("substituted helper\n"), 0o700)
			},
			want: "bundle member",
		},
		{
			name: "missing required helper entry",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				fixture.omitManifestPath(t, fixture.layout.sshdSessionPath)
			},
			want: "omits required sshd-session",
		},
		{
			name: "missing required OpenSSL license entry",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				fixture.omitManifestPath(t, fixture.layout.openSSLLicensePath)
			},
			want: "omits required OpenSSL license",
		},
		{
			name: "unexpected bundle entry",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				fixture.addUnexpectedManifestPath(t)
			},
			want: "contains unexpected path",
		},
		{
			name: "receipt build hardening",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				receipt := readServerTestFile(t, fixture.layout.sourceReceiptPath)
				receipt = []byte(strings.Replace(string(receipt), "hardening=yes\n", "hardening=no\n", 1))
				writeServerTestFile(t, fixture.layout.sourceReceiptPath, receipt, 0o600)
				fixture.resealBundle(t)
			},
			want: "receipt hardening",
		},
		{
			name: "OpenSSL receipt tests",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				receipt := readServerTestFile(t, fixture.layout.openSSLReceiptPath)
				receipt = []byte(strings.Replace(string(receipt), "tests=passed\n", "tests=failed\n", 1))
				writeServerTestFile(t, fixture.layout.openSSLReceiptPath, receipt, 0o600)
				fixture.resealBundle(t)
			},
			want: "OpenSSL source receipt tests",
		},
		{
			name: "wrong exact version",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.version = []byte("OpenSSH_10.4p2, OpenSSL 3.5.7 9 Jun 2026\n")
			},
			want: "sshd -V stderr",
		},
		{
			name: "version on stdout",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.versionStdout = append([]byte(nil), fixture.runner.version...)
				fixture.runner.version = nil
			},
			want: "sshd -V wrote unexpected stdout",
		},
		{
			name: "dynamic libcrypto executable",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.inspector.err = errors.New("OpenSSH ELF dynamically depends on forbidden OpenSSL library libcrypto.so.3")
			},
			want: "dynamically depends on forbidden OpenSSL",
		},
		{
			name: "dynamic libssl executable",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.inspector.err = errors.New("OpenSSH ELF dynamically depends on forbidden OpenSSL library libssl.so.3")
			},
			want: "dynamically depends on forbidden OpenSSL",
		},
		{
			name: "executable RPATH",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.inspector.err = errors.New("OpenSSH ELF contains forbidden RPATH")
			},
			want: "forbidden RPATH",
		},
		{
			name: "executable RUNPATH",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.inspector.err = errors.New("OpenSSH ELF contains forbidden RUNPATH")
			},
			want: "forbidden RUNPATH",
		},
		{
			name: "late executable linkage evidence change",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.inspector.changedAfter = 5
				fixture.inspector.changed = executableLinkageReport{
					format:           profile.ExecutableFormat,
					openSSLLinkage:   profile.OpenSSLLinkage,
					dynamicLibraries: []string{"libc.so.6", "libm.so.6"},
				}
			},
			want: "linkage evidence changed",
		},
		{
			name: "rendered configuration",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				writeServerTestFile(t, fixture.layout.serverConfigPath, []byte("Port 22\n"), 0o600)
			},
			want: "does not byte-for-byte match",
		},
		{
			name: "host key algorithm",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.hostPublicKey = []byte("ssh-ed25519 AAAA\n")
			},
			want: "host public-key type",
		},
		{
			name: "managed authorization",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				writeServerTestFile(t, fixture.layout.authorizedKeysPath, []byte("not managed\n"), 0o600)
			},
			want: "validate managed authorized_keys",
		},
		{
			name: "effective forwarding policy",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.effective = []byte(strings.Replace(
					string(fixture.runner.effective),
					"allowtcpforwarding local\n",
					"allowtcpforwarding yes\n",
					1,
				))
			},
			want: "option allowtcpforwarding",
		},
		{
			name: "effective algorithm fallback",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.effective = []byte(strings.Replace(
					string(fixture.runner.effective),
					"kexalgorithms mlkem768x25519-sha256\n",
					"kexalgorithms mlkem768x25519-sha256,curve25519-sha256\n",
					1,
				))
			},
			want: "option kexalgorithms",
		},
		{
			name: "effective rekey policy",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.effective = []byte(strings.Replace(
					string(fixture.runner.effective),
					"rekeylimit 536870912 3600\n",
					"rekeylimit 0 0\n",
					1,
				))
			},
			want: "option rekeylimit",
		},
		{
			name: "unexpected sshd test diagnostics",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.testStderr = []byte("warning\n")
			},
			want: "sshd -t emitted unexpected",
		},
		{
			name: "unsafe helper mode",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				if err := os.Chmod(fixture.layout.sshdAuthPath, 0o722); err != nil {
					t.Fatalf("chmod helper: %v", err)
				}
			},
			want: "permissions",
		},
		{
			name: "authorized keys symlink",
			mutate: func(t *testing.T, fixture *serverPreflightFixture) {
				realPath := fixture.layout.authorizedKeysPath + ".real"
				if err := os.Rename(fixture.layout.authorizedKeysPath, realPath); err != nil {
					t.Fatalf("rename authorized_keys: %v", err)
				}
				if err := os.Symlink(realPath, fixture.layout.authorizedKeysPath); err != nil {
					t.Fatalf("symlink authorized_keys: %v", err)
				}
			},
			want: "must not be a symbolic link",
		},
		{
			name: "final helper substitution",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.before = func(commandPath string, arguments []string) error {
					if commandPath != fixture.layout.sshdPath || len(arguments) == 0 || arguments[0] != "-T" {
						return nil
					}
					fixture.runner.before = nil
					return os.WriteFile(fixture.layout.sshdSessionPath, []byte("late substitution\n"), 0o700)
				}
			},
			want: "changed during preflight",
		},
		{
			name: "final private host key substitution",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.before = func(commandPath string, arguments []string) error {
					if commandPath != fixture.layout.sshdPath || len(arguments) == 0 || arguments[0] != "-T" {
						return nil
					}
					fixture.runner.before = nil
					return os.WriteFile(
						fixture.layout.hostKeyPath,
						[]byte("late private host key substitution with a different size\n"),
						0o600,
					)
				}
			},
			want: "server host private key",
		},
		{
			name: "late fixed-path ancestor substitution",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.runner.before = func(commandPath string, arguments []string) error {
					if commandPath != fixture.layout.sshdPath || len(arguments) == 0 || arguments[0] != "-T" {
						return nil
					}
					fixture.runner.before = nil
					directory := filepath.Dir(fixture.layout.authorizedKeysPath)
					realDirectory := directory + ".real"
					if err := os.Rename(directory, realDirectory); err != nil {
						return err
					}
					return os.Symlink(realDirectory, directory)
				}
			},
			want: "fixed-path ancestor",
		},
		{
			name: "late Unix account database substitution",
			mutate: func(_ *testing.T, fixture *serverPreflightFixture) {
				fixture.accounts.changeAfterFirst = true
			},
			want: "account databases changed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServerPreflightFixture(t)
			test.mutate(t, fixture)

			_, err := preflightServer(
				context.Background(),
				fixture.config,
				fixture.dependencies(),
			)
			if err == nil {
				t.Fatal("preflightServer accepted a substituted or unsafe server installation")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflightServer error = %q, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseBundleManifestRequiresCanonicalAuthenticatedInventory(t *testing.T) {
	validPath := "opt/warptweet/libexec/openssh/bin/ssh-keygen"
	digest := strings.Repeat("a", 64)
	valid := []byte(digest + "  " + validPath + "\n")
	if _, err := parseBundleManifest(valid); err != nil {
		t.Fatalf("parseBundleManifest(valid): %v", err)
	}

	tests := []struct {
		name     string
		contents string
	}{
		{name: "not terminated", contents: digest + "  " + validPath},
		{name: "uppercase digest", contents: strings.Repeat("A", 64) + "  " + validPath + "\n"},
		{name: "one separator space", contents: digest + " " + validPath + "\n"},
		{name: "absolute path", contents: digest + "  /" + validPath + "\n"},
		{name: "traversal path", contents: digest + "  opt/warptweet/libexec/openssh/../outside\n"},
		{name: "outside tree", contents: digest + "  etc/passwd\n"},
		{
			name: "duplicate",
			contents: digest + "  " + validPath + "\n" +
				digest + "  " + validPath + "\n",
		},
		{
			name: "unsorted",
			contents: digest + "  opt/warptweet/libexec/openssh/sbin/sshd\n" +
				digest + "  " + validPath + "\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseBundleManifest([]byte(test.contents)); err == nil {
				t.Fatal("parseBundleManifest accepted a noncanonical inventory")
			}
		})
	}
}

func TestParseServerSourceReceiptsRequiresExactOrderedSchemas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		valid []byte
		parse func([]byte) (map[string]string, error)
	}{
		{
			name:  "OpenSSH",
			valid: serverTestSourceReceipt(strings.Repeat("a", 64)),
			parse: parseOpenSSHSourceReceipt,
		},
		{
			name:  "OpenSSL",
			valid: serverTestOpenSSLSourceReceipt("x86_64"),
			parse: parseOpenSSLSourceReceipt,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := test.parse(test.valid); err != nil {
				t.Fatalf("parse valid receipt: %v", err)
			}
			lines := strings.Split(strings.TrimSuffix(string(test.valid), "\n"), "\n")
			controlByte := append([]byte(nil), test.valid[:len(test.valid)-1]...)
			controlByte = append(controlByte, 0x00, '\n')
			mutations := map[string][]byte{
				"missing field":  []byte(strings.Join(lines[:len(lines)-1], "\n") + "\n"),
				"extra field":    append(append([]byte(nil), test.valid...), []byte("extra=value\n")...),
				"not terminated": append([]byte(nil), test.valid[:len(test.valid)-1]...),
				"control byte":   controlByte,
			}
			reordered := append([]string(nil), lines...)
			reordered[0], reordered[1] = reordered[1], reordered[0]
			mutations["reordered fields"] = []byte(strings.Join(reordered, "\n") + "\n")
			for name, contents := range mutations {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					if _, err := test.parse(contents); err == nil {
						t.Fatal("parser accepted a noncanonical receipt")
					}
				})
			}
		})
	}
}

func TestValidateServerSourceReceiptsBindsStaticNativeBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		platform     string
		architecture string
		mutate       func(map[string]string, map[string]string)
		wantError    string
	}{
		{name: "valid x86_64", platform: "linux", architecture: "x86_64"},
		{
			name:         "valid aarch64",
			platform:     "linux",
			architecture: "aarch64",
			mutate: func(openSSH, openSSL map[string]string) {
				openSSH["target_tuple"] = "aarch64-unknown-linux-gnu"
				openSSL["architecture"] = "aarch64"
			},
		},
		{
			name:         "non-Linux platform",
			platform:     "darwin",
			architecture: "x86_64",
			wantError:    "want linux",
		},
		{
			name:         "unsupported architecture",
			platform:     "linux",
			architecture: "riscv64",
			wantError:    "want x86_64 or aarch64",
		},
		{
			name:         "receipt architecture mismatch",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(_ map[string]string, openSSL map[string]string) {
				openSSL["architecture"] = "aarch64"
			},
			wantError: "OpenSSL source receipt architecture",
		},
		{
			name:         "target tuple architecture mismatch",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(openSSH, _ map[string]string) {
				openSSH["target_tuple"] = "aarch64-unknown-linux-gnu"
			},
			wantError: "target_tuple",
		},
		{
			name:         "unsafe target tuple",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(openSSH, _ map[string]string) {
				openSSH["target_tuple"] = "x86_64 unknown-linux-gnu"
			},
			wantError: "unsafe character",
		},
		{
			name:         "OpenSSH tests not passed",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(openSSH, _ map[string]string) {
				openSSH["tests"] = "failed"
			},
			wantError: "OpenSSH source receipt tests",
		},
		{
			name:         "OpenSSL signer",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(_ map[string]string, openSSL map[string]string) {
				openSSL["release_key_fingerprint"] = strings.Repeat("0", 40)
			},
			wantError: "OpenSSL source receipt release_key_fingerprint",
		},
		{
			name:         "dynamic OpenSSL receipt",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(_ map[string]string, openSSL map[string]string) {
				openSSL["linkage"] = "dynamic"
			},
			wantError: "OpenSSL source receipt linkage",
		},
		{
			name:         "uppercase static libcrypto digest",
			platform:     "linux",
			architecture: "x86_64",
			mutate: func(_ map[string]string, openSSL map[string]string) {
				openSSL["static_libcrypto_sha256"] = strings.Repeat("D", 64)
			},
			wantError: "static_libcrypto_sha256",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			openSSH, err := parseOpenSSHSourceReceipt(serverTestSourceReceipt(strings.Repeat("a", 64)))
			if err != nil {
				t.Fatalf("parse OpenSSH receipt: %v", err)
			}
			openSSL, err := parseOpenSSLSourceReceipt(serverTestOpenSSLSourceReceipt("x86_64"))
			if err != nil {
				t.Fatalf("parse OpenSSL receipt: %v", err)
			}
			if test.mutate != nil {
				test.mutate(openSSH, openSSL)
			}
			evidence, err := validateServerSourceReceipts(
				openSSH,
				openSSL,
				strings.Repeat("a", 64),
				test.platform,
				test.architecture,
			)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateServerSourceReceipts: %v", err)
				}
				if evidence.staticLibcryptoSHA256 != strings.Repeat("d", 64) {
					t.Fatalf("static libcrypto digest = %q", evidence.staticLibcryptoSHA256)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestValidateServerVersionOutputRequiresExactStreams(t *testing.T) {
	t.Parallel()

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	exact := []byte(selected.EngineVersion + ", " + selected.OpenSSLVersionText + "\n")
	tests := []struct {
		name   string
		result serverCommandResult
		valid  bool
	}{
		{name: "exact stderr", result: serverCommandResult{stderr: exact}, valid: true},
		{name: "stdout", result: serverCommandResult{stdout: exact}},
		{name: "missing LF", result: serverCommandResult{stderr: exact[:len(exact)-1]}},
		{name: "extra whitespace", result: serverCommandResult{stderr: append(append([]byte(nil), exact[:len(exact)-1]...), ' ', '\n')}},
		{name: "wrong OpenSSL", result: serverCommandResult{stderr: []byte(selected.EngineVersion + ", OpenSSL 3.5.6 7 Apr 2026\n")}},
		{name: "extra line", result: serverCommandResult{stderr: append(append([]byte(nil), exact...), []byte("banner\n")...)}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			version, err := validateServerVersionOutput(test.result, selected)
			if test.valid {
				if err != nil || version != selected.EngineVersion {
					t.Fatalf("validateServerVersionOutput = %q, %v", version, err)
				}
				return
			}
			if err == nil {
				t.Fatal("validateServerVersionOutput accepted non-exact streams")
			}
		})
	}
}

func TestParseEffectiveServerOptionsNormalizesPinnedOpenSSHCasing(t *testing.T) {
	t.Parallel()

	options, err := parseEffectiveServerOptions([]byte(
		"port 2222\nAddressFamily inet\nLoginGraceTime 30\nX11DisplayOffset 10\n",
	))
	if err != nil {
		t.Fatalf("parseEffectiveServerOptions: %v", err)
	}
	for key, want := range map[string]string{
		"port":             "2222",
		"addressfamily":    "inet",
		"logingracetime":   "30",
		"x11displayoffset": "10",
	} {
		if got := options[key]; !slices.Equal(got, []string{want}) {
			t.Errorf("option %s = %q, want %q", key, got, want)
		}
	}
}

func TestParseEffectiveServerOptionsRejectsUnsafeNamesAndValues(t *testing.T) {
	t.Parallel()

	for _, output := range [][]byte{
		[]byte("Address-Family inet\n"),
		[]byte("AddressFamily  inet\n"),
		[]byte("AddressFamily inet \n"),
		[]byte("AddressFamily\tinet\n"),
	} {
		if _, err := parseEffectiveServerOptions(output); err == nil {
			t.Fatalf("parseEffectiveServerOptions accepted unsafe output %q", output)
		}
	}
}

type serverPreflightFixture struct {
	config            server.Config
	layout            serverPreflightLayout
	runner            *fakeServerCommandRunner
	inspector         *fakeServerExecutableInspector
	environment       []string
	platform          string
	architecture      string
	hostPublicKey     []byte
	accounts          *fakeServerAccountInspector
	privsepOwnerCalls int
	privsepOwnerErr   error
}

func newServerPreflightFixture(t *testing.T) *serverPreflightFixture {
	t.Helper()

	stageRoot := t.TempDir()
	layout := serverPreflightLayout{
		stageRoot:          stageRoot,
		sshPath:            physicalPathForLogical(stageRoot, installlayout.SSHPath),
		sshdPath:           physicalPathForLogical(stageRoot, installlayout.SSHDPath),
		sshdAuthPath:       physicalPathForLogical(stageRoot, installlayout.SSHDAuthPath),
		sshdSessionPath:    physicalPathForLogical(stageRoot, installlayout.SSHDSessionPath),
		sshKeygenPath:      physicalPathForLogical(stageRoot, installlayout.SSHKeygenPath),
		bundleManifestPath: physicalPathForLogical(stageRoot, installlayout.OpenSSHBundleManifestPath),
		sourceReceiptPath:  physicalPathForLogical(stageRoot, installlayout.OpenSSHSourceReceiptPath),
		openSSLReceiptPath: physicalPathForLogical(stageRoot, installlayout.OpenSSLSourceReceiptPath),
		openSSHLicensePath: physicalPathForLogical(stageRoot, installlayout.OpenSSHLicensePath),
		openSSLLicensePath: physicalPathForLogical(stageRoot, installlayout.OpenSSLLicensePath),
		serverConfigPath:   physicalPathForLogical(stageRoot, installlayout.ServerConfigPath),
		hostKeyPath:        physicalPathForLogical(stageRoot, installlayout.ServerHostKeyPath),
		authorizedKeysPath: physicalPathForLogical(
			stageRoot,
			installlayout.AuthorizedKeysDirectory+"/"+server.DefaultDedicatedUser,
		),
		privsepDirectory: physicalPathForLogical(stageRoot, installlayout.PrivsepDirectory),
	}
	config := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            strings.Repeat("0", 64),
		OpenSSHBundleManifestSHA256: strings.Repeat("0", 64),
		Listen: server.Endpoint{
			Address: netip.MustParseAddr("192.0.2.10"),
			Port:    2222,
		},
		Target: server.Endpoint{
			Address: netip.MustParseAddr("198.51.100.7"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: installlayout.AuthorizedKeysDirectory + "/" + server.DefaultDedicatedUser,
	}

	writeServerTestFile(t, layout.sshPath, []byte("fake ssh 10.4p1\n"), 0o700)
	writeServerTestFile(t, layout.sshdPath, []byte("fake sshd 10.4p1\n"), 0o700)
	writeServerTestFile(t, layout.sshdAuthPath, []byte("fake sshd-auth 10.4p1\n"), 0o700)
	writeServerTestFile(t, layout.sshdSessionPath, []byte("fake sshd-session 10.4p1\n"), 0o700)
	writeServerTestFile(t, layout.sshKeygenPath, []byte("fake ssh-keygen 10.4p1\n"), 0o700)
	writeServerTestFile(t, layout.hostKeyPath, []byte("test composite private key\n"), 0o600)
	if err := os.MkdirAll(layout.privsepDirectory, 0o755); err != nil {
		t.Fatalf("MkdirAll privilege-separation directory: %v", err)
	}
	if err := os.Chmod(layout.privsepDirectory, 0o755); err != nil {
		t.Fatalf("Chmod privilege-separation directory: %v", err)
	}

	config.SSHDBinarySHA256 = serverTestSHA256(readServerTestFile(t, layout.sshdPath))
	writeServerTestFile(
		t,
		layout.sourceReceiptPath,
		serverTestSourceReceipt(config.SSHDBinarySHA256),
		0o600,
	)
	writeServerTestFile(t, layout.openSSLReceiptPath, serverTestOpenSSLSourceReceipt("x86_64"), 0o600)
	writeServerTestFile(t, layout.openSSHLicensePath, []byte("authenticated OpenSSH license\n"), 0o600)
	writeServerTestFile(t, layout.openSSLLicensePath, []byte("authenticated OpenSSL license\n"), 0o600)

	fixture := &serverPreflightFixture{
		config: config,
		layout: layout,
		accounts: &fakeServerAccountInspector{evidence: serverAccountEvidence{
			dedicatedUID: 900,
			dedicatedGID: 900,
			privsepUID:   901,
			privsepGID:   901,
		}},
	}
	fixture.resealBundle(t)

	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	publicKeyBlob := serverTestPublicKeyBlob(selected, 0x42)
	plainPublicKey := []byte(selected.AuthenticationKeyType + " " + publicKeyBlob + "\n")
	authorizedKey, err := server.RenderAuthorizedKey(fixture.config, plainPublicKey)
	if err != nil {
		t.Fatalf("server.RenderAuthorizedKey: %v", err)
	}
	writeServerTestFile(t, layout.authorizedKeysPath, authorizedKey, 0o600)

	renderedConfig, err := server.Render(fixture.config)
	if err != nil {
		t.Fatalf("server.Render: %v", err)
	}
	writeServerTestFile(t, layout.serverConfigPath, renderedConfig, 0o600)

	fixture.hostPublicKey = plainPublicKey
	fixture.inspector = &fakeServerExecutableInspector{
		report: executableLinkageReport{
			format:           profile.ExecutableFormat,
			openSSLLinkage:   profile.OpenSSLLinkage,
			dynamicLibraries: []string{"libc.so.6"},
		},
		paths: make(map[string]int),
	}
	fixture.environment = []string{
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"LD_PRELOAD=/tmp/interpose.so",
		"LD_LIBRARY_PATH=/tmp/lib",
		"DYLD_INSERT_LIBRARIES=/tmp/interpose.dylib",
		"OPENSSL_CONF=/tmp/openssl.cnf",
		"OPENSSL_MODULES=/tmp/providers",
		"LIBPATH=/tmp/lib",
		"SHLIB_PATH=/tmp/lib",
		"MALFORMED",
	}
	fixture.platform = "linux"
	fixture.architecture = "x86_64"
	fixture.runner = &fakeServerCommandRunner{
		layout:        layout,
		version:       []byte(selected.EngineVersion + ", " + selected.OpenSSLVersionText + "\n"),
		hostPublicKey: plainPublicKey,
		effective:     serverTestEffectiveOutput(fixture.config, selected),
	}
	return fixture
}

func (fixture *serverPreflightFixture) dependencies() serverPreflightDependencies {
	return serverPreflightDependencies{
		layout:    fixture.layout,
		runner:    fixture.runner,
		inspector: fixture.inspector,
		environment: func() []string {
			return append([]string(nil), fixture.environment...)
		},
		platform:     fixture.platform,
		architecture: fixture.architecture,
		ownerValidator: func(_ string, _ os.FileInfo) error {
			return nil
		},
		privsepOwnerValidator: func(_ string, _ os.FileInfo) error {
			fixture.privsepOwnerCalls++
			return fixture.privsepOwnerErr
		},
		accountInspector: fixture.accounts.Inspect,
	}
}

type fakeServerAccountInspector struct {
	evidence         serverAccountEvidence
	err              error
	changeAfterFirst bool
	calls            int
}

func (inspector *fakeServerAccountInspector) Inspect(_ string) (serverAccountEvidence, error) {
	inspector.calls++
	if inspector.err != nil {
		return serverAccountEvidence{}, inspector.err
	}
	evidence := inspector.evidence
	if inspector.changeAfterFirst && inspector.calls > 1 {
		evidence.passwdSHA256[0]++
	}
	return evidence, nil
}

func (fixture *serverPreflightFixture) resealBundle(t *testing.T) {
	t.Helper()

	paths := []string{
		fixture.layout.sshPath,
		fixture.layout.sshdPath,
		fixture.layout.sshdAuthPath,
		fixture.layout.sshdSessionPath,
		fixture.layout.sshKeygenPath,
		fixture.layout.sourceReceiptPath,
		fixture.layout.openSSLReceiptPath,
		fixture.layout.openSSHLicensePath,
		fixture.layout.openSSLLicensePath,
	}
	hashes := make(map[string]string, len(paths))
	relativePaths := make([]string, 0, len(paths))
	for _, assetPath := range paths {
		relative, err := filepath.Rel(fixture.layout.stageRoot, assetPath)
		if err != nil {
			t.Fatalf("filepath.Rel: %v", err)
		}
		relative = filepath.ToSlash(relative)
		hashes[relative] = serverTestSHA256(readServerTestFile(t, assetPath))
		relativePaths = append(relativePaths, relative)
	}
	sort.Strings(relativePaths)
	lines := make([]string, 0, len(relativePaths))
	for _, relative := range relativePaths {
		lines = append(lines, hashes[relative]+"  "+relative)
	}
	manifest := []byte(strings.Join(lines, "\n") + "\n")
	writeServerTestFile(t, fixture.layout.bundleManifestPath, manifest, 0o600)
	fixture.config.OpenSSHBundleManifestSHA256 = serverTestSHA256(manifest)
}

func (fixture *serverPreflightFixture) addUnexpectedManifestPath(t *testing.T) {
	t.Helper()

	unexpectedPath := physicalPathForLogical(
		fixture.layout.stageRoot,
		installlayout.OpenSSHPrefix+"/bin/ssh-keyscan",
	)
	writeServerTestFile(t, unexpectedPath, []byte("unexpected bundle executable\n"), 0o700)
	relative, err := filepath.Rel(fixture.layout.stageRoot, unexpectedPath)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	line := serverTestSHA256(readServerTestFile(t, unexpectedPath)) + "  " + filepath.ToSlash(relative)
	contents := readServerTestFile(t, fixture.layout.bundleManifestPath)
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	lines = append(lines, line)
	sort.Slice(lines, func(left, right int) bool {
		return strings.SplitN(lines[left], "  ", 2)[1] < strings.SplitN(lines[right], "  ", 2)[1]
	})
	manifest := []byte(strings.Join(lines, "\n") + "\n")
	writeServerTestFile(t, fixture.layout.bundleManifestPath, manifest, 0o600)
	fixture.config.OpenSSHBundleManifestSHA256 = serverTestSHA256(manifest)
}

func (fixture *serverPreflightFixture) omitManifestPath(t *testing.T, assetPath string) {
	t.Helper()

	relative, err := filepath.Rel(fixture.layout.stageRoot, assetPath)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	wantSuffix := "  " + filepath.ToSlash(relative)
	contents := readServerTestFile(t, fixture.layout.bundleManifestPath)
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if !strings.HasSuffix(line, wantSuffix) {
			filtered = append(filtered, line)
		}
	}
	if len(filtered) == len(lines) {
		t.Fatalf("bundle manifest does not contain %q", relative)
	}
	manifest := []byte(strings.Join(filtered, "\n") + "\n")
	writeServerTestFile(t, fixture.layout.bundleManifestPath, manifest, 0o600)
	fixture.config.OpenSSHBundleManifestSHA256 = serverTestSHA256(manifest)
}

type fakeServerCommandRunner struct {
	layout        serverPreflightLayout
	version       []byte
	versionStdout []byte
	hostPublicKey []byte
	effective     []byte
	testStderr    []byte
	before        func(string, []string) error
	environments  [][]string
	calls         int
}

type fakeServerExecutableInspector struct {
	report       executableLinkageReport
	err          error
	changedAfter int
	changed      executableLinkageReport
	paths        map[string]int
	calls        int
}

func (inspector *fakeServerExecutableInspector) Inspect(file *os.File) (executableLinkageReport, error) {
	inspector.calls++
	if file != nil {
		inspector.paths[file.Name()]++
	}
	if inspector.err != nil {
		return executableLinkageReport{}, inspector.err
	}
	if inspector.changedAfter > 0 && inspector.calls > inspector.changedAfter {
		return inspector.changed, nil
	}
	return inspector.report, nil
}

func (runner *fakeServerCommandRunner) Run(
	_ context.Context,
	commandPath string,
	environment []string,
	arguments ...string,
) (serverCommandResult, error) {
	runner.calls++
	runner.environments = append(runner.environments, append([]string(nil), environment...))
	if runner.before != nil {
		if err := runner.before(commandPath, arguments); err != nil {
			return serverCommandResult{}, err
		}
	}

	switch {
	case commandPath == runner.layout.sshdPath && equalServerTestArguments(arguments, "-V"):
		return serverCommandResult{
			stdout: append([]byte(nil), runner.versionStdout...),
			stderr: append([]byte(nil), runner.version...),
		}, nil
	case commandPath == runner.layout.sshKeygenPath && equalServerTestArguments(
		arguments,
		"-y",
		"-f",
		runner.layout.hostKeyPath,
	):
		return serverCommandResult{stdout: append([]byte(nil), runner.hostPublicKey...)}, nil
	case commandPath == runner.layout.sshdPath && equalServerTestArguments(
		arguments,
		"-t",
		"-f",
		runner.layout.serverConfigPath,
	):
		return serverCommandResult{stderr: append([]byte(nil), runner.testStderr...)}, nil
	case commandPath == runner.layout.sshdPath && equalServerTestArguments(
		arguments,
		"-T",
		"-f",
		runner.layout.serverConfigPath,
	):
		return serverCommandResult{stdout: append([]byte(nil), runner.effective...)}, nil
	default:
		return serverCommandResult{}, fmt.Errorf("unexpected command %q with arguments %q", commandPath, arguments)
	}
}

func equalServerTestArguments(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func serverTestEffectiveOutput(config server.Config, selected profile.Profile) []byte {
	listenAddress := config.Listen.Address.Unmap()
	addressFamily := "inet6"
	listen := "[" + listenAddress.String() + "]:" + fmt.Sprint(config.Listen.Port)
	if listenAddress.Is4() {
		addressFamily = "inet"
		listen = listenAddress.String() + ":" + fmt.Sprint(config.Listen.Port)
	}
	target := netip.AddrPortFrom(config.Target.Address.Unmap(), uint16(config.Target.Port)).String()
	lines := []string{
		"addressfamily " + addressFamily,
		"port " + fmt.Sprint(config.Listen.Port),
		"listenaddress " + listen,
		"pidfile " + expectedServerPIDFile,
		"hostkey " + config.HostKeyPath,
		"hostkeyalgorithms " + selected.AuthenticationKeyType,
		"kexalgorithms " + selected.KeyExchangeAlgorithm,
		"pubkeyacceptedalgorithms " + selected.AuthenticationKeyType,
		"ciphers " + strings.Join(selected.Ciphers, ","),
		"rekeylimit 536870912 3600",
		"compression no",
		"authenticationmethods publickey",
		"pubkeyauthentication yes",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"hostbasedauthentication no",
		"permitemptypasswords no",
		"permitrootlogin no",
		"strictmodes yes",
		"allowusers " + config.DedicatedUser,
		"authorizedkeysfile " + config.AuthorizedKeysPath,
		"maxauthtries 3",
		"logingracetime 30",
		"maxstartups 10:30:60",
		"maxsessions 0",
		"allowtcpforwarding local",
		"permitopen " + target,
		"permitlisten none",
		"allowstreamlocalforwarding no",
		"allowagentforwarding no",
		"x11forwarding no",
		"permittty no",
		"permittunnel no",
		"gatewayports no",
		"permituserrc no",
		"permituserenvironment no",
		"exposeauthinfo no",
		"printlastlog no",
		"printmotd no",
		"usedns no",
		"tcpkeepalive no",
		"clientaliveinterval 30",
		"clientalivecountmax 3",
		"versionaddendum none",
		"loglevel VERBOSE",
		"disableforwarding no",
		"forcecommand none",
		"chrootdirectory none",
		"authorizedkeyscommand none",
		"authorizedprincipalscommand none",
		"authorizedprincipalsfile none",
		"trustedusercakeys none",
		"hostkeyagent none",
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func serverTestPublicKeyBlob(selected profile.Profile, fill byte) string {
	algorithm := []byte(selected.AuthenticationKeyType)
	raw := make([]byte, selected.RawPublicKeyBytes)
	for index := range raw {
		raw[index] = fill
	}
	blob := make([]byte, 4+len(algorithm)+4+len(raw))
	binary.BigEndian.PutUint32(blob[:4], uint32(len(algorithm)))
	copy(blob[4:], algorithm)
	offset := 4 + len(algorithm)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(raw)))
	copy(blob[offset+4:], raw)
	return base64.StdEncoding.EncodeToString(blob)
}

func serverTestSourceReceipt(sshdSHA256 string) []byte {
	lines := []string{
		"receipt_version=1",
		"version=" + opensshsource.Version,
		"engine_version=" + opensshsource.EngineVersion,
		"source_url=" + opensshsource.SourceURL,
		"source_sha256=" + opensshsource.SourceSHA256,
		"release_key_fingerprint=" + opensshsource.ReleaseKeyFingerprint,
		"configure_prefix=" + installlayout.OpenSSHPrefix,
		"sysconfdir=" + expectedOpenSSHSysconfDir,
		"privsep_user=" + installlayout.PrivsepUser,
		"privsep_path=" + installlayout.PrivsepDirectory,
		"hardening=yes",
		"pie=yes",
		"kerberos5=no",
		"ldns=no",
		"libedit=no",
		"pam=no",
		"selinux=no",
		"zlib=no",
		"sshd_path=" + installlayout.SSHDPath,
		"sshd_sha256=" + sshdSHA256,
		"target_tuple=x86_64-pc-linux-gnu",
		"openssl_prefix=" + opensslsource.LogicalPrefix,
		"openssl_source_receipt_path=" + installlayout.OpenSSLSourceReceiptPath,
		"openssl_source_sha256=" + opensslsource.SourceSHA256,
		"openssl_linkage=static",
		"elf_dynamic_policy=passed",
		"tests=passed",
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func serverTestOpenSSLSourceReceipt(architecture string) []byte {
	lines := []string{
		"receipt_version=1",
		"version=" + opensslsource.Version,
		"source_url=" + opensslsource.SourceURL,
		"source_sha256=" + opensslsource.SourceSHA256,
		"release_key_fingerprint=" + opensslsource.ReleaseKeyFingerprint,
		"platform=linux",
		"architecture=" + architecture,
		"configure_prefix=" + opensslsource.LogicalPrefix,
		"openssl_config_directory=" + opensslsource.LogicalConfigDirectory,
		"shared=no",
		"module=no",
		"dso=no",
		"pinshared=no",
		"tests=passed",
		"linkage=static",
		"static_libcrypto_sha256=" + strings.Repeat("d", 64),
		"license_path=" + installlayout.OpenSSLLicensePath,
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func serverTestSHA256(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func writeServerTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%q): %v", path, err)
	}
}

func readServerTestFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return contents
}
