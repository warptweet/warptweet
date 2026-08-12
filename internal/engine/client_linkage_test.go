package engine

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/profile"
)

type fixedExecutableInspector struct {
	report executableLinkageReport
	err    error
}

type recordingClientCommandRunner struct {
	calls int
}

func (runner *recordingClientCommandRunner) Run(
	context.Context,
	string,
	[]string,
	...string,
) (clientCommandOutput, error) {
	runner.calls++
	return clientCommandOutput{}, nil
}

func (inspector fixedExecutableInspector) Inspect(*os.File) (executableLinkageReport, error) {
	return inspector.report, inspector.err
}

func TestValidateELFLinkageRequiresStaticOpenSSLAndClosedSearchPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    elf.Type
		needed  []string
		rpath   []string
		runpath []string
		valid   bool
	}{
		{name: "ET_EXEC", kind: elf.ET_EXEC, needed: []string{"libc.so.6", "libz.so.1"}, valid: true},
		{name: "PIE ET_DYN", kind: elf.ET_DYN, needed: []string{"libc.so.6"}, valid: true},
		{name: "relocatable", kind: elf.ET_REL},
		{name: "RPATH", kind: elf.ET_EXEC, rpath: []string{"/opt/openssl/lib"}},
		{name: "RUNPATH", kind: elf.ET_DYN, runpath: []string{"$ORIGIN"}},
		{name: "libcrypto unversioned", kind: elf.ET_EXEC, needed: []string{"libcrypto.so"}},
		{name: "libcrypto versioned", kind: elf.ET_EXEC, needed: []string{"libcrypto.so.3"}},
		{name: "libssl unversioned", kind: elf.ET_EXEC, needed: []string{"libssl.so"}},
		{name: "libssl versioned path", kind: elf.ET_EXEC, needed: []string{"/unsafe/libssl.so.3"}},
		{name: "unsafe needed", kind: elf.ET_EXEC, needed: []string{"libc.so.6\nmalformed"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report, err := validateELFLinkage(test.kind, test.needed, test.rpath, test.runpath)
			if test.valid {
				if err != nil {
					t.Fatalf("validateELFLinkage: %v", err)
				}
				wantNeeded := append([]string(nil), test.needed...)
				slices.Sort(wantNeeded)
				if report.format != "ELF" || report.openSSLLinkage != "static" ||
					!slices.Equal(report.dynamicLibraries, wantNeeded) {
					t.Fatalf("unexpected linkage report: %#v", report)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateELFLinkage accepted unsafe ELF evidence: %#v", report)
			}
		})
	}
}

func TestELFExecutableInspectorParsesHeldFileCrossPlatform(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "minimal-elf")
	if err := os.WriteFile(path, minimalELF64(elf.ET_EXEC), 0o700); err != nil {
		t.Fatalf("write minimal ELF: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open minimal ELF: %v", err)
	}
	defer file.Close()
	report, err := (elfExecutableInspector{}).Inspect(file)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if report.format != "ELF" || report.openSSLLinkage != "static" ||
		report.dynamicLibraries == nil || len(report.dynamicLibraries) != 0 {
		t.Fatalf("unexpected minimal ELF report: %#v", report)
	}
}

func TestSanitizedClientEnvironmentUsesDeterministicMinimalAllowlist(t *testing.T) {
	t.Parallel()

	input := []string{
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"LD_PRELOAD=/tmp/interpose.so",
		"LD_LIBRARY_PATH=/tmp/lib",
		"DYLD_INSERT_LIBRARIES=/tmp/interpose.dylib",
		"OPENSSL_CONF=/tmp/openssl.cnf",
		"OPENSSL_MODULES=/tmp/providers",
		"LIBPATH=/tmp/lib",
		"SHLIB_PATH=/tmp/lib",
		"GLIBC_TUNABLES=glibc.malloc.check=3",
		"LOCPATH=/tmp/locale",
		"MALLOC_CHECK_=3",
		"SSH_AUTH_SOCK=/tmp/agent",
		"MALFORMED",
	}
	want := []string{"LANG=C", "LC_ALL=C"}
	if got := sanitizedClientEnvironment(input); !slices.Equal(got, want) {
		t.Fatalf("sanitized environment = %q, want %q", got, want)
	}
	if got := sanitizedClientEnvironment(nil); !slices.Equal(got, want) || got == nil {
		t.Fatalf("nil-input environment = %q, want non-nil %q", got, want)
	}
}

func TestPreflightReportEqualIncludesDependencyEvidence(t *testing.T) {
	t.Parallel()

	left := PreflightReport{
		Path:               "/opt/warptweet/ssh",
		SHA256:             strings.Repeat("a", 64),
		Version:            "OpenSSH_10.4p1",
		Profile:            "profile",
		ArtifactProfileID:  "linux-amd64",
		OpenSSLVersion:     "3.5.7",
		OpenSSLVersionText: "OpenSSL 3.5.7 9 Jun 2026",
		OpenSSLLinkage:     "static",
		ExecutableFormat:   "ELF",
		DynamicLibraries:   []string{"libc.so.6"},
	}
	right := left
	right.DynamicLibraries = append([]string(nil), left.DynamicLibraries...)
	if !left.Equal(right) {
		t.Fatal("Equal rejected identical attestation evidence")
	}
	mutations := []struct {
		name   string
		mutate func(*PreflightReport)
	}{
		{name: "path", mutate: func(value *PreflightReport) { value.Path += ".changed" }},
		{name: "sha256", mutate: func(value *PreflightReport) { value.SHA256 = strings.Repeat("b", 64) }},
		{name: "version", mutate: func(value *PreflightReport) { value.Version += ".changed" }},
		{name: "profile", mutate: func(value *PreflightReport) { value.Profile += ".changed" }},
		{name: "artifact profile", mutate: func(value *PreflightReport) { value.ArtifactProfileID = "linux-arm64" }},
		{name: "openssl version", mutate: func(value *PreflightReport) { value.OpenSSLVersion = "3.5.8" }},
		{name: "openssl version text", mutate: func(value *PreflightReport) { value.OpenSSLVersionText += ".changed" }},
		{name: "openssl linkage", mutate: func(value *PreflightReport) { value.OpenSSLLinkage = "dynamic" }},
		{name: "executable format", mutate: func(value *PreflightReport) { value.ExecutableFormat = "Mach-O" }},
		{name: "dynamic libraries", mutate: func(value *PreflightReport) {
			value.DynamicLibraries = append(value.DynamicLibraries, "libcrypto.so.3")
		}},
	}
	for _, test := range mutations {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			changed := right
			changed.DynamicLibraries = append([]string(nil), right.DynamicLibraries...)
			test.mutate(&changed)
			if left.Equal(changed) {
				t.Fatal("Equal ignored changed attestation evidence")
			}
		})
	}
}

func TestPreflightRejectsInspectorFailureBeforeExecution(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ssh")
	contents := []byte("synthetic executable")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	runner := &recordingClientCommandRunner{}
	dependencies := clientPreflightDependencies{
		runner:      runner,
		inspector:   fixedExecutableInspector{err: errors.New("dynamic OpenSSL dependency")},
		environment: func() []string { return nil },
	}
	digestBytes := sha256.Sum256(contents)
	digest := hex.EncodeToString(digestBytes[:])
	if _, err := preflightWithDependencies(
		context.Background(),
		Binary{Path: path, SHA256: digest},
		selected,
		dependencies,
	); err == nil || !strings.Contains(err.Error(), "dynamic OpenSSL dependency") {
		t.Fatalf("Preflight error = %v, want inspector failure", err)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want zero", runner.calls)
	}
}

func minimalELF64(fileType elf.Type) []byte {
	const headerSize = 64
	header := make([]byte, headerSize)
	copy(header[:4], []byte{0x7f, 'E', 'L', 'F'})
	header[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(header[16:18], uint16(fileType))
	binary.LittleEndian.PutUint16(header[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(header[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(header[52:54], headerSize)
	binary.LittleEndian.PutUint16(header[54:56], 56)
	binary.LittleEndian.PutUint16(header[58:60], 64)
	return header
}
