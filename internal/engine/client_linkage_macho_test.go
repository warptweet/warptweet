package engine

import (
	"debug/macho"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMachOLinkageAcceptsSystemOnlyExecutable(t *testing.T) {
	t.Parallel()

	file := &macho.File{
		FileHeader: macho.FileHeader{
			Type: macho.TypeExec,
			Cpu:  macho.Cpu(machOCPUTypeARM64),
		},
		Loads: []macho.Load{
			&macho.Dylib{Name: "/usr/lib/libSystem.B.dylib"},
		},
	}
	report, err := validateMachOLinkage(file, "arm64")
	if err != nil {
		t.Fatalf("validateMachOLinkage: %v", err)
	}
	if report.format != machOFormat || report.openSSLLinkage != staticOpenSSLLinkage {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.dynamicLibraries) != 1 || report.dynamicLibraries[0] != "/usr/lib/libSystem.B.dylib" {
		t.Fatalf("unexpected libraries: %#v", report.dynamicLibraries)
	}
}

func TestValidateMachOLinkageRejectsForbiddenLoaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file *macho.File
		arch string
		want string
	}{
		{
			name: "rpath",
			file: &macho.File{
				FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.Cpu(machOCPUTypeARM64)},
				Loads:      []macho.Load{&macho.Rpath{Path: "/opt/evil"}},
			},
			arch: "arm64",
			want: "LC_RPATH",
		},
		{
			name: "libcrypto",
			file: &macho.File{
				FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.Cpu(machOCPUTypeARM64)},
				Loads:      []macho.Load{&macho.Dylib{Name: "/usr/local/opt/openssl/lib/libcrypto.3.dylib"}},
			},
			arch: "arm64",
			want: "forbidden OpenSSL",
		},
		{
			name: "at rpath",
			file: &macho.File{
				FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.Cpu(machOCPUTypeARM64)},
				Loads:      []macho.Load{&macho.Dylib{Name: "@rpath/libfoo.dylib"}},
			},
			arch: "arm64",
			want: "relative loader path",
		},
		{
			name: "non-system absolute",
			file: &macho.File{
				FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.Cpu(machOCPUTypeARM64)},
				Loads:      []macho.Load{&macho.Dylib{Name: "/opt/homebrew/lib/libfoo.dylib"}},
			},
			arch: "arm64",
			want: "non-system absolute",
		},
		{
			name: "wrong cpu",
			file: &macho.File{
				FileHeader: macho.FileHeader{Type: macho.TypeExec, Cpu: macho.Cpu(machOCPUTypeX86_64)},
			},
			arch: "arm64",
			want: "not arm64",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateMachOLinkage(test.file, test.arch)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateMachOLinkageRejectsFatMagic(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "fat")
	if err := os.WriteFile(path, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0}, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()

	_, err = (machoExecutableInspector{}).Inspect(file)
	if err == nil || !strings.Contains(err.Error(), "universal") {
		t.Fatalf("error = %v, want universal rejection", err)
	}
}
