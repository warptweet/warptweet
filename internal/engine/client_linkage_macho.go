package engine

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
)

const (
	machOFormat        = "Mach-O"
	machOCPUTypeX86_64 = 0x01000007
	machOCPUTypeARM64  = 0x0100000c
	machOMagic64       = 0xfeedfacf
	machOCigam64       = 0xcffaedfe
	machOFatMagic      = 0xcafebabe
	machOFatCigam      = 0xbebafeca
)

// machoExecutableInspector parses the already-open executable rather than a
// caller-controlled pathname. The pure Mach-O policy is platform-independent so
// it remains directly testable on Linux CI.
type machoExecutableInspector struct{}

func (machoExecutableInspector) Inspect(file *os.File) (executableLinkageReport, error) {
	if file == nil {
		return executableLinkageReport{}, errors.New("inspect OpenSSH executable linkage: file is nil")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return executableLinkageReport{}, fmt.Errorf("rewind OpenSSH executable for Mach-O inspection: %w", err)
	}

	var magic uint32
	if err := binary.Read(file, binary.BigEndian, &magic); err != nil {
		return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH Mach-O magic: %w", err)
	}
	// Fat magic is stored big-endian on disk.
	if magic == machOFatMagic || magic == machOFatCigam {
		return executableLinkageReport{}, errors.New("OpenSSH Mach-O universal binaries are forbidden until each slice is independently authenticated")
	}
	if magic != machOMagic64 && magic != machOCigam64 {
		// Also accept little-endian interpretation of the 64-bit magics.
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return executableLinkageReport{}, fmt.Errorf("rewind OpenSSH executable after magic inspection: %w", err)
		}
		var little uint32
		if err := binary.Read(file, binary.LittleEndian, &little); err != nil {
			return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH Mach-O magic: %w", err)
		}
		if little != machOMagic64 && little != machOCigam64 {
			return executableLinkageReport{}, fmt.Errorf("OpenSSH executable is not a 64-bit Mach-O file (magic 0x%x)", magic)
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return executableLinkageReport{}, fmt.Errorf("rewind OpenSSH executable after magic inspection: %w", err)
	}

	parsed, err := macho.NewFile(file)
	if err != nil {
		return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH executable as Mach-O: %w", err)
	}
	defer parsed.Close()

	return validateMachOLinkage(parsed, runtime.GOARCH)
}

func validateMachOLinkage(file *macho.File, goarch string) (executableLinkageReport, error) {
	if file == nil {
		return executableLinkageReport{}, errors.New("inspect OpenSSH Mach-O linkage: file is nil")
	}
	if file.Type != macho.TypeExec {
		return executableLinkageReport{}, fmt.Errorf("OpenSSH Mach-O type is %s, want MH_EXECUTE", file.Type)
	}
	if err := requireNativeMachOCPU(uint32(file.Cpu), goarch); err != nil {
		return executableLinkageReport{}, err
	}

	var dynamicLibraries []string
	for _, load := range file.Loads {
		switch command := load.(type) {
		case *macho.Rpath:
			return executableLinkageReport{}, errors.New("OpenSSH Mach-O contains forbidden LC_RPATH")
		case *macho.Dylib:
			if err := validateMachODylibName(command.Name); err != nil {
				return executableLinkageReport{}, err
			}
			dynamicLibraries = append(dynamicLibraries, command.Name)
		}
	}

	sort.Strings(dynamicLibraries)
	return executableLinkageReport{
		format:           machOFormat,
		openSSLLinkage:   staticOpenSSLLinkage,
		dynamicLibraries: dynamicLibraries,
	}, nil
}

func requireNativeMachOCPU(cpu uint32, goarch string) error {
	switch goarch {
	case "arm64":
		if cpu != machOCPUTypeARM64 {
			return fmt.Errorf("OpenSSH Mach-O CPU type 0x%x is not arm64", cpu)
		}
	case "amd64":
		if cpu != machOCPUTypeX86_64 {
			return fmt.Errorf("OpenSSH Mach-O CPU type 0x%x is not x86_64", cpu)
		}
	default:
		return fmt.Errorf("OpenSSH Mach-O inspection does not support GOARCH %q", goarch)
	}
	return nil
}

func validateMachODylibName(name string) error {
	if name == "" || strings.ContainsAny(name, "\x00\r\n") {
		return fmt.Errorf("OpenSSH Mach-O contains unsafe dylib name %q", name)
	}
	base := path.Base(name)
	if isDynamicOpenSSLMachOLibrary(base) {
		return fmt.Errorf("OpenSSH Mach-O dynamically depends on forbidden OpenSSL library %q", name)
	}
	if strings.HasPrefix(name, "@rpath/") ||
		strings.HasPrefix(name, "@loader_path/") ||
		strings.HasPrefix(name, "@executable_path/") {
		return fmt.Errorf("OpenSSH Mach-O contains forbidden relative loader path %q", name)
	}
	if strings.HasPrefix(name, "/") &&
		!strings.HasPrefix(name, "/usr/lib/") &&
		!strings.HasPrefix(name, "/System/Library/") {
		return fmt.Errorf("OpenSSH Mach-O depends on non-system absolute library %q", name)
	}
	return nil
}

func isDynamicOpenSSLMachOLibrary(base string) bool {
	lower := strings.ToLower(base)
	return lower == "libcrypto.dylib" ||
		strings.HasPrefix(lower, "libcrypto.") ||
		lower == "libssl.dylib" ||
		strings.HasPrefix(lower, "libssl.")
}
