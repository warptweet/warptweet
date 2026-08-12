package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type executableInspectorFunc func(*os.File) (executableLinkageReport, error)

func (inspect executableInspectorFunc) Inspect(file *os.File) (executableLinkageReport, error) {
	return inspect(file)
}

func TestProductionClientLayoutRejectsAlternatePathBeforeInspection(t *testing.T) {
	t.Parallel()

	_, err := holdProductionClientLayout(
		"/usr/bin/ssh",
		func(os.FileInfo) (bool, error) { return true, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "must be exactly") {
		t.Fatalf("holdProductionClientLayout error = %v, want fixed-path rejection", err)
	}
}

func TestHeldClientLayoutDetectsDirectorySubstitution(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "bin")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		t.Fatalf("Stat: %v", err)
	}
	held := &heldClientLayout{
		ancestors: []heldClientAncestor{{path: path, file: file, info: info}},
		ownershipChecker: func(os.FileInfo) (bool, error) {
			return true, nil
		},
	}
	t.Cleanup(held.close)

	moved := path + ".original"
	if err := os.Rename(path, moved); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir replacement: %v", err)
	}
	if err := held.verify(); err == nil || !strings.Contains(err.Error(), "substituted") {
		t.Fatalf("verify error = %v, want substitution rejection", err)
	}
}

func TestValidateFixedClientAncestorRejectsWritableOrUnownedDirectory(t *testing.T) {
	t.Parallel()

	path := t.TempDir()
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if err := validateFixedClientAncestor(
		path,
		info,
		func(os.FileInfo) (bool, error) { return true, nil },
	); err == nil || !strings.Contains(err.Error(), "group or world writable") {
		t.Fatalf("writable ancestor error = %v", err)
	}

	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if err := validateFixedClientAncestor(
		path,
		info,
		func(os.FileInfo) (bool, error) { return false, nil },
	); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("unowned ancestor error = %v", err)
	}
}

func TestExecutableSnapshotRequiresRootOwnershipWhenEnabled(t *testing.T) {
	t.Parallel()

	path, binary := writeSnapshotExecutable(t, []byte("synthetic executable"))
	_, err := inspectClientExecutable(
		binary,
		fixedExecutableInspector{report: validStaticLinkageReport()},
		true,
		func(os.FileInfo) (bool, error) { return false, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("inspectClientExecutable(%q) error = %v, want root-owner rejection", path, err)
	}
}

func TestExecutableSnapshotRehashesAfterELFInspection(t *testing.T) {
	t.Parallel()

	path, binary := writeSnapshotExecutable(t, []byte("synthetic executable"))
	inspector := executableInspectorFunc(func(*os.File) (executableLinkageReport, error) {
		if err := os.WriteFile(path, []byte("changed executable contents"), 0o700); err != nil {
			return executableLinkageReport{}, err
		}
		return validStaticLinkageReport(), nil
	})
	_, err := inspectClientExecutable(binary, inspector, false, nil)
	if err == nil || !strings.Contains(err.Error(), "content or metadata changed") {
		t.Fatalf("inspectClientExecutable error = %v, want post-inspection rehash rejection", err)
	}
}

func TestExecutableSnapshotComparesMetadataAfterELFInspection(t *testing.T) {
	t.Parallel()

	path, binary := writeSnapshotExecutable(t, []byte("synthetic executable"))
	inspector := executableInspectorFunc(func(*os.File) (executableLinkageReport, error) {
		changed := time.Unix(1, 0)
		if err := os.Chtimes(path, changed, changed); err != nil {
			return executableLinkageReport{}, err
		}
		return validStaticLinkageReport(), nil
	})
	_, err := inspectClientExecutable(binary, inspector, false, nil)
	if err == nil || !strings.Contains(err.Error(), "content or metadata changed") {
		t.Fatalf("inspectClientExecutable error = %v, want metadata-change rejection", err)
	}
}

func TestExecutableSnapshotPropagatesOwnershipInspectionError(t *testing.T) {
	t.Parallel()

	_, binary := writeSnapshotExecutable(t, []byte("synthetic executable"))
	_, err := inspectClientExecutable(
		binary,
		fixedExecutableInspector{report: validStaticLinkageReport()},
		true,
		func(os.FileInfo) (bool, error) { return false, errors.New("unavailable") },
	)
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("inspectClientExecutable error = %v, want ownership error", err)
	}
}

func writeSnapshotExecutable(t *testing.T, contents []byte) (string, Binary) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	digest := sha256.Sum256(contents)
	return path, Binary{Path: path, SHA256: hex.EncodeToString(digest[:])}
}

func validStaticLinkageReport() executableLinkageReport {
	return executableLinkageReport{
		format:           "ELF",
		openSSLLinkage:   "static",
		dynamicLibraries: []string{"libc.so.6"},
	}
}
