package engine

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
)

const staticOpenSSLLinkage = "static"

type executableLinkageReport struct {
	format           string
	openSSLLinkage   string
	dynamicLibraries []string
}

func (report executableLinkageReport) equal(other executableLinkageReport) bool {
	return report.format == other.format &&
		report.openSSLLinkage == other.openSSLLinkage &&
		slices.Equal(report.dynamicLibraries, other.dynamicLibraries)
}

type executableInspector interface {
	Inspect(*os.File) (executableLinkageReport, error)
}

// elfExecutableInspector parses the already-open executable rather than a
// caller-controlled pathname. debug/elf is platform-independent, which keeps
// this production Linux policy directly testable on macOS.
type elfExecutableInspector struct{}

func (elfExecutableInspector) Inspect(file *os.File) (executableLinkageReport, error) {
	if file == nil {
		return executableLinkageReport{}, errors.New("inspect OpenSSH executable linkage: file is nil")
	}
	parsed, err := elf.NewFile(file)
	if err != nil {
		return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH executable as ELF: %w", err)
	}
	defer parsed.Close()

	needed, err := parsed.ImportedLibraries()
	if err != nil {
		return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH ELF dynamic dependencies: %w", err)
	}
	rpath, err := parsed.DynString(elf.DT_RPATH)
	if err != nil {
		return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH ELF RPATH: %w", err)
	}
	runpath, err := parsed.DynString(elf.DT_RUNPATH)
	if err != nil {
		return executableLinkageReport{}, fmt.Errorf("inspect OpenSSH ELF RUNPATH: %w", err)
	}
	return validateELFLinkage(parsed.Type, needed, rpath, runpath)
}

func validateELFLinkage(
	fileType elf.Type,
	needed []string,
	rpath []string,
	runpath []string,
) (executableLinkageReport, error) {
	if fileType != elf.ET_EXEC && fileType != elf.ET_DYN {
		return executableLinkageReport{}, fmt.Errorf(
			"OpenSSH ELF type is %s, want ET_EXEC or ET_DYN",
			fileType,
		)
	}
	if len(rpath) != 0 {
		return executableLinkageReport{}, fmt.Errorf("OpenSSH ELF contains forbidden RPATH %q", rpath)
	}
	if len(runpath) != 0 {
		return executableLinkageReport{}, fmt.Errorf("OpenSSH ELF contains forbidden RUNPATH %q", runpath)
	}

	dynamicLibraries := append([]string{}, needed...)
	sort.Strings(dynamicLibraries)
	for _, library := range dynamicLibraries {
		if library == "" || strings.ContainsAny(library, "\x00\r\n") {
			return executableLinkageReport{}, fmt.Errorf("OpenSSH ELF contains unsafe DT_NEEDED entry %q", library)
		}
		if isDynamicOpenSSLLibrary(library) {
			return executableLinkageReport{}, fmt.Errorf(
				"OpenSSH ELF dynamically depends on forbidden OpenSSL library %q",
				library,
			)
		}
	}

	return executableLinkageReport{
		format:           "ELF",
		openSSLLinkage:   staticOpenSSLLinkage,
		dynamicLibraries: dynamicLibraries,
	}, nil
}

func isDynamicOpenSSLLibrary(value string) bool {
	base := strings.ToLower(path.Base(value))
	return base == "libcrypto.so" || strings.HasPrefix(base, "libcrypto.so.") ||
		base == "libssl.so" || strings.HasPrefix(base, "libssl.so.")
}
