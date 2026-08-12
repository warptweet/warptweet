package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

// canonicalReadinessDirectory permits only a protected system-root symlink
// such as Darwin's /var -> /private/var, then rejects symlinks in all remaining
// path components.
func canonicalReadinessDirectory(
	path string,
	ancestorOwner fileOwnershipChecker,
) (string, error) {
	if runtime.GOOS == "js" || runtime.GOOS == "plan9" {
		return "", fmt.Errorf("descriptor-anchored readiness directories are unsupported on %s", runtime.GOOS)
	}
	if ancestorOwner == nil {
		return "", errors.New("readiness ancestor ownership checker is required")
	}
	rootPath, components, err := validateAbsoluteReadinessPath(path)
	if err != nil {
		return "", err
	}

	firstPath := filepath.Join(rootPath, components[0])
	before, err := os.Lstat(firstPath)
	if err != nil {
		return "", fmt.Errorf("inspect readiness root component: %w", err)
	}
	if before.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		return "", fmt.Errorf("inspect filesystem root: %w", err)
	}
	if err := validateReadinessAncestor(rootInfo, ancestorOwner); err != nil {
		return "", fmt.Errorf("readiness root symlink is beneath an unsafe filesystem root: %w", err)
	}
	beforeTarget, err := os.Readlink(firstPath)
	if err != nil {
		return "", fmt.Errorf("read readiness root symlink: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(firstPath)
	if err != nil {
		return "", fmt.Errorf("resolve protected readiness root symlink: %w", err)
	}
	after, err := os.Lstat(firstPath)
	if err != nil {
		return "", fmt.Errorf("reinspect readiness root symlink: %w", err)
	}
	afterTarget, err := os.Readlink(firstPath)
	if err != nil {
		return "", fmt.Errorf("reread readiness root symlink: %w", err)
	}
	if after.Mode()&os.ModeSymlink == 0 || !os.SameFile(before, after) || beforeTarget != afterTarget {
		return "", errors.New("readiness root symlink changed while it was resolved")
	}

	canonical := resolved
	for _, component := range components[1:] {
		canonical = filepath.Join(canonical, component)
	}
	if _, _, err := validateAbsoluteReadinessPath(canonical); err != nil {
		return "", fmt.Errorf("resolved readiness directory is unsafe: %w", err)
	}
	return canonical, nil
}

func validateAbsoluteReadinessPath(path string) (string, []string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, errors.New("readiness directory must be an absolute clean path")
	}
	volume := filepath.VolumeName(path)
	rootPath := volume + string(os.PathSeparator)
	relative, err := filepath.Rel(rootPath, path)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", nil, errors.New("readiness directory must be below a filesystem root")
	}
	components := strings.Split(relative, string(os.PathSeparator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return "", nil, errors.New("readiness directory contains an unsafe path component")
		}
		for _, character := range component {
			if unicode.IsControl(character) {
				return "", nil, errors.New("readiness directory contains a control character")
			}
		}
	}
	return rootPath, components, nil
}

func openReadinessDirectory(
	path string,
	ancestorOwner fileOwnershipChecker,
) (*os.Root, error) {
	if ancestorOwner == nil {
		return nil, errors.New("readiness ancestor ownership checker is required")
	}
	rootPath, components, err := validateAbsoluteReadinessPath(path)
	if err != nil {
		return nil, err
	}
	current, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	rootInfo, err := current.Stat(".")
	if err != nil {
		_ = current.Close()
		return nil, fmt.Errorf("inspect filesystem root handle: %w", err)
	}
	if err := validateReadinessAncestor(rootInfo, ancestorOwner); err != nil {
		_ = current.Close()
		return nil, fmt.Errorf("filesystem root is unsafe: %w", err)
	}
	for index, component := range components {
		next, openErr := openRealReadinessDirectory(current, component)
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		if closeErr := current.Close(); closeErr != nil {
			_ = next.Close()
			return nil, fmt.Errorf("close parent readiness directory handle: %w", closeErr)
		}
		current = next
		if index < len(components)-1 {
			info, statErr := current.Stat(".")
			if statErr != nil {
				_ = current.Close()
				return nil, fmt.Errorf("inspect readiness ancestor %q: %w", component, statErr)
			}
			if validationErr := validateReadinessAncestor(info, ancestorOwner); validationErr != nil {
				_ = current.Close()
				return nil, fmt.Errorf("readiness ancestor %q is unsafe: %w", component, validationErr)
			}
		}
	}
	return current, nil
}

func validateReadinessAncestor(
	info os.FileInfo,
	owner fileOwnershipChecker,
) error {
	if !info.IsDir() {
		return errors.New("ancestor is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("permissions %04o permit replacement by another principal", info.Mode().Perm())
	}
	owned, err := owner(info)
	if err != nil {
		return fmt.Errorf("inspect ancestor ownership: %w", err)
	}
	if !owned {
		return errors.New("ancestor must be owned by root")
	}
	return nil
}

func openRealReadinessDirectory(parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect readiness directory component %q: %w", name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, fmt.Errorf("readiness directory component %q must be a real directory", name)
	}

	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open readiness directory component %q: %w", name, err)
	}
	opened, openedErr := child.Stat(".")
	after, afterErr := parent.Lstat(name)
	if openedErr != nil || afterErr != nil {
		_ = child.Close()
		return nil, fmt.Errorf("reinspect readiness directory component %q", name)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.IsDir() ||
		!os.SameFile(before, after) || !os.SameFile(after, opened) {
		_ = child.Close()
		return nil, fmt.Errorf("readiness directory component %q changed while it was opened", name)
	}
	return child, nil
}
