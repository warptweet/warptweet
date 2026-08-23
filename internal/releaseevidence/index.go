package releaseevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Cell is one required client/server artifact-profile pair.
type Cell struct {
	Client string
	Server string
}

// RequiredMatrixCells returns the cartesian product of checklist matrix profiles.
func RequiredMatrixCells(checklist Checklist) []Cell {
	var cells []Cell
	for _, client := range checklist.Matrix.ClientArtifactProfiles {
		for _, server := range checklist.Matrix.ServerArtifactProfiles {
			cells = append(cells, Cell{Client: client, Server: server})
		}
	}
	return cells
}

// ValidateIndex checks that reports cover every matrix cell exactly once.
func ValidateIndex(checklist Checklist, reports []ReportV2) error {
	required := map[string]struct{}{}
	for _, cell := range RequiredMatrixCells(checklist) {
		required[cell.Client+"/"+cell.Server] = struct{}{}
	}
	if len(required) == 0 {
		return fmt.Errorf("checklist matrix is empty")
	}
	seen := map[string]struct{}{}
	for i, report := range reports {
		if err := ValidateReportV2(checklist, report); err != nil {
			return fmt.Errorf("report %d: %w", i, err)
		}
		key := report.ClientArtifactProfileID + "/" + report.ServerArtifactProfileID
		if _, ok := required[key]; !ok {
			return fmt.Errorf("unknown matrix cell %s", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate matrix cell %s", key)
		}
		seen[key] = struct{}{}
	}
	var missing []string
	for _, cell := range RequiredMatrixCells(checklist) {
		key := cell.Client + "/" + cell.Server
		if _, ok := seen[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("missing matrix cells: %s", strings.Join(missing, ", "))
	}
	return nil
}

// CompleteIndex reports whether every cell passed.
func CompleteIndex(reports []ReportV2) bool {
	if len(reports) == 0 {
		return false
	}
	for _, report := range reports {
		if !CompleteV2(report) {
			return false
		}
	}
	return true
}

// BindArtifactDigests hashes the named package files and requires they match the report.
func BindArtifactDigests(repositoryRoot string, report ReportV2) error {
	if report.ClientPackagePath == "" || report.ServerPackagePath == "" {
		return fmt.Errorf("client_package_path and server_package_path are required")
	}
	clientPath, err := containedRegularFile(repositoryRoot, report.ClientPackagePath)
	if err != nil {
		return fmt.Errorf("client package: %w", err)
	}
	serverPath, err := containedRegularFile(repositoryRoot, report.ServerPackagePath)
	if err != nil {
		return fmt.Errorf("server package: %w", err)
	}
	got, err := fileSHA256(clientPath)
	if err != nil {
		return fmt.Errorf("client package: %w", err)
	}
	if got != report.ClientPackageSHA256 {
		return fmt.Errorf("client_package_sha256 does not match %s", report.ClientPackagePath)
	}
	got, err = fileSHA256(serverPath)
	if err != nil {
		return fmt.Errorf("server package: %w", err)
	}
	if got != report.ServerPackageSHA256 {
		return fmt.Errorf("server_package_sha256 does not match %s", report.ServerPackagePath)
	}
	return nil
}

func containedRegularFile(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path must be repository-relative")
	}
	cleaned := filepath.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root")
	}
	full := filepath.Join(root, cleaned)
	info, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("path is a symlink")
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path is not a regular file")
	}
	return full, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
