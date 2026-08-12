package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type serverAncestorSnapshot struct {
	path string
	file *os.File
	info os.FileInfo
}

// serverAncestorSet retains an open descriptor for every directory from the
// injected stage root through each fixed asset's parent. These descriptors do
// not make path-based execve atomic, but they preserve stable identity evidence
// and make any persistent ancestor substitution detectable.
type serverAncestorSet struct {
	entries []serverAncestorSnapshot
}

func snapshotServerAncestors(
	layout serverPreflightLayout,
	ownerValidator serverOwnerValidator,
) (*serverAncestorSet, error) {
	paths, err := serverAncestorPaths(layout)
	if err != nil {
		return nil, err
	}
	result := &serverAncestorSet{entries: make([]serverAncestorSnapshot, 0, len(paths))}
	for _, directoryPath := range paths {
		snapshot, snapshotErr := snapshotServerAncestor(directoryPath, ownerValidator)
		if snapshotErr != nil {
			_ = result.Close()
			return nil, snapshotErr
		}
		result.entries = append(result.entries, snapshot)
	}
	return result, nil
}

func serverAncestorPaths(layout serverPreflightLayout) ([]string, error) {
	unique := map[string]struct{}{layout.stageRoot: {}}
	parents := make([]string, 0, len(serverLayoutAssetPaths(layout))+1)
	for _, assetPath := range serverLayoutAssetPaths(layout) {
		parents = append(parents, filepath.Dir(assetPath))
	}
	parents = append(parents, layout.privsepDirectory)
	for _, parent := range parents {
		relative, err := filepath.Rel(layout.stageRoot, parent)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("preflight server: fixed asset parent %q escapes stage root", parent)
		}
		if relative == "." {
			continue
		}
		current := layout.stageRoot
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			if component == "" || component == "." || component == ".." {
				return nil, fmt.Errorf("preflight server: fixed asset parent %q is not canonical", parent)
			}
			current = filepath.Join(current, component)
			unique[current] = struct{}{}
		}
	}
	paths := make([]string, 0, len(unique))
	for directoryPath := range unique {
		paths = append(paths, directoryPath)
	}
	sort.Slice(paths, func(left, right int) bool {
		leftDepth := strings.Count(paths[left], string(filepath.Separator))
		rightDepth := strings.Count(paths[right], string(filepath.Separator))
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return paths[left] < paths[right]
	})
	return paths, nil
}

func (ancestors *serverAncestorSet) RequireDirectoryMode(
	directoryPath string,
	want os.FileMode,
	ownerValidator serverOwnerValidator,
) error {
	if ancestors == nil {
		return errors.New("preflight server: fixed-path ancestor evidence is nil")
	}
	for _, entry := range ancestors.entries {
		if entry.path != directoryPath {
			continue
		}
		if err := verifyHeldServerAncestor(entry, ownerValidator); err != nil {
			return err
		}
		if entry.info.Mode().Perm() != want.Perm() {
			return fmt.Errorf(
				"preflight server: fixed-path directory %q permissions are %04o, want %04o",
				directoryPath,
				entry.info.Mode().Perm(),
				want.Perm(),
			)
		}
		return nil
	}
	return fmt.Errorf("preflight server: fixed-path directory %q is not anchored", directoryPath)
}

func serverLayoutAssetPaths(layout serverPreflightLayout) []string {
	return []string{
		layout.sshPath,
		layout.sshdPath,
		layout.sshdAuthPath,
		layout.sshdSessionPath,
		layout.sshKeygenPath,
		layout.bundleManifestPath,
		layout.sourceReceiptPath,
		layout.openSSLReceiptPath,
		layout.openSSHLicensePath,
		layout.openSSLLicensePath,
		layout.serverConfigPath,
		layout.hostKeyPath,
		layout.authorizedKeysPath,
	}
}

func snapshotServerAncestor(
	directoryPath string,
	ownerValidator serverOwnerValidator,
) (serverAncestorSnapshot, error) {
	pathInfo, err := os.Lstat(directoryPath)
	if err != nil {
		return serverAncestorSnapshot{}, fmt.Errorf(
			"preflight server: inspect fixed-path ancestor %q: %w",
			directoryPath,
			err,
		)
	}
	if err := validateServerAncestorInfo(directoryPath, pathInfo, ownerValidator); err != nil {
		return serverAncestorSnapshot{}, err
	}
	file, err := os.Open(directoryPath)
	if err != nil {
		return serverAncestorSnapshot{}, fmt.Errorf(
			"preflight server: open fixed-path ancestor %q: %w",
			directoryPath,
			err,
		)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return serverAncestorSnapshot{}, fmt.Errorf(
			"preflight server: inspect opened fixed-path ancestor %q: %w",
			directoryPath,
			err,
		)
	}
	if err := validateServerAncestorInfo(directoryPath, openedInfo, ownerValidator); err != nil {
		_ = file.Close()
		return serverAncestorSnapshot{}, err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return serverAncestorSnapshot{}, fmt.Errorf(
			"preflight server: fixed-path ancestor %q was replaced while opening",
			directoryPath,
		)
	}
	if pathInfo.Mode() != openedInfo.Mode() {
		_ = file.Close()
		return serverAncestorSnapshot{}, fmt.Errorf(
			"preflight server: fixed-path ancestor %q changed mode while opening",
			directoryPath,
		)
	}
	return serverAncestorSnapshot{path: directoryPath, file: file, info: openedInfo}, nil
}

func validateServerAncestorInfo(
	directoryPath string,
	info os.FileInfo,
	ownerValidator serverOwnerValidator,
) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("preflight server: fixed-path ancestor %q must not be a symbolic link", directoryPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("preflight server: fixed-path ancestor %q must be a directory", directoryPath)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("preflight server: fixed-path ancestor %q has unsafe special mode bits", directoryPath)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"preflight server: fixed-path ancestor %q permissions %04o permit group or world writes",
			directoryPath,
			info.Mode().Perm(),
		)
	}
	if err := ownerValidator(directoryPath, info); err != nil {
		return fmt.Errorf("preflight server: fixed-path ancestor %q: %w", directoryPath, err)
	}
	return nil
}

func (ancestors *serverAncestorSet) Verify(ownerValidator serverOwnerValidator) error {
	if ancestors == nil {
		return errors.New("preflight server: fixed-path ancestor evidence is nil")
	}
	for _, initial := range ancestors.entries {
		if err := verifyHeldServerAncestor(initial, ownerValidator); err != nil {
			return err
		}
	}
	return nil
}

func verifyHeldServerAncestor(
	initial serverAncestorSnapshot,
	ownerValidator serverOwnerValidator,
) error {
	pathInfo, err := os.Lstat(initial.path)
	if err != nil {
		return fmt.Errorf("preflight server: re-inspect fixed-path ancestor %q: %w", initial.path, err)
	}
	if err := validateServerAncestorInfo(initial.path, pathInfo, ownerValidator); err != nil {
		return err
	}
	heldInfo, err := initial.file.Stat()
	if err != nil {
		return fmt.Errorf("preflight server: inspect held fixed-path ancestor %q: %w", initial.path, err)
	}
	if err := validateServerAncestorInfo(initial.path, heldInfo, ownerValidator); err != nil {
		return err
	}
	if !os.SameFile(initial.info, heldInfo) || !os.SameFile(initial.info, pathInfo) {
		return fmt.Errorf("preflight server: fixed-path ancestor %q was substituted", initial.path)
	}
	if initial.info.Mode() != heldInfo.Mode() || initial.info.Mode() != pathInfo.Mode() {
		return fmt.Errorf("preflight server: fixed-path ancestor %q changed mode", initial.path)
	}
	return nil
}

func (ancestors *serverAncestorSet) Close() error {
	if ancestors == nil {
		return nil
	}
	var result error
	for index := len(ancestors.entries) - 1; index >= 0; index-- {
		if err := ancestors.entries[index].file.Close(); err != nil && result == nil {
			result = err
		}
	}
	ancestors.entries = nil
	return result
}
