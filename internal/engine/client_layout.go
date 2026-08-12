package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"warptweet.com/warptweet/internal/installlayout"
)

type heldClientAncestor struct {
	path string
	file *os.File
	info os.FileInfo
}

type heldClientLayout struct {
	ancestors        []heldClientAncestor
	ownershipChecker fileOwnershipChecker
}

type fileOwnershipChecker func(os.FileInfo) (bool, error)

func holdProductionClientLayout(
	binaryPath string,
	ownershipChecker fileOwnershipChecker,
) (*heldClientLayout, error) {
	return holdProductionClientLayoutAt(binaryPath, installlayout.SSHPath, ownershipChecker)
}

func holdProductionClientLayoutAt(
	binaryPath string,
	expectedSSHPath string,
	ownershipChecker fileOwnershipChecker,
) (*heldClientLayout, error) {
	if expectedSSHPath == "" {
		return nil, errors.New("fixed OpenSSH path is required")
	}
	if binaryPath != expectedSSHPath {
		return nil, fmt.Errorf(
			"production OpenSSH binary path must be exactly %q",
			expectedSSHPath,
		)
	}

	if ownershipChecker == nil {
		return nil, errors.New("fixed OpenSSH ancestor ownership checker is required")
	}
	held := &heldClientLayout{ownershipChecker: ownershipChecker}
	for _, ancestorPath := range fixedPathAncestors(binaryPath) {
		info, err := os.Lstat(ancestorPath)
		if err != nil {
			held.close()
			return nil, fmt.Errorf("inspect fixed OpenSSH ancestor %q: %w", ancestorPath, err)
		}
		if err := validateFixedClientAncestor(ancestorPath, info, ownershipChecker); err != nil {
			held.close()
			return nil, err
		}
		file, err := os.Open(ancestorPath)
		if err != nil {
			held.close()
			return nil, fmt.Errorf("open fixed OpenSSH ancestor %q: %w", ancestorPath, err)
		}
		openedInfo, err := file.Stat()
		if err != nil {
			file.Close()
			held.close()
			return nil, fmt.Errorf("inspect opened OpenSSH ancestor %q: %w", ancestorPath, err)
		}
		currentInfo, err := os.Lstat(ancestorPath)
		if err != nil || !os.SameFile(info, openedInfo) || !os.SameFile(info, currentInfo) {
			file.Close()
			held.close()
			return nil, fmt.Errorf("fixed OpenSSH ancestor %q changed while it was opened", ancestorPath)
		}
		if err := validateFixedClientAncestor(ancestorPath, currentInfo, ownershipChecker); err != nil {
			file.Close()
			held.close()
			return nil, err
		}
		held.ancestors = append(held.ancestors, heldClientAncestor{
			path: ancestorPath,
			file: file,
			info: openedInfo,
		})
	}
	return held, nil
}

func (held *heldClientLayout) verify() error {
	if held == nil || len(held.ancestors) == 0 {
		return errors.New("fixed OpenSSH ancestor set is empty")
	}
	for _, ancestor := range held.ancestors {
		openedInfo, err := ancestor.file.Stat()
		if err != nil {
			return fmt.Errorf("reinspect held OpenSSH ancestor %q: %w", ancestor.path, err)
		}
		currentInfo, err := os.Lstat(ancestor.path)
		if err != nil {
			return fmt.Errorf("reinspect fixed OpenSSH ancestor %q: %w", ancestor.path, err)
		}
		if !os.SameFile(ancestor.info, openedInfo) || !os.SameFile(ancestor.info, currentInfo) {
			return fmt.Errorf("fixed OpenSSH ancestor %q was substituted", ancestor.path)
		}
		if err := validateFixedClientAncestor(
			ancestor.path,
			currentInfo,
			held.ownershipChecker,
		); err != nil {
			return err
		}
	}
	return nil
}

func (held *heldClientLayout) close() {
	if held == nil {
		return
	}
	for index := len(held.ancestors) - 1; index >= 0; index-- {
		_ = held.ancestors[index].file.Close()
	}
	held.ancestors = nil
}

func validateFixedClientAncestor(
	path string,
	info os.FileInfo,
	ownershipChecker fileOwnershipChecker,
) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("fixed OpenSSH ancestor %q must be a non-symlink directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("fixed OpenSSH ancestor %q must not be group or world writable", path)
	}
	if ownershipChecker == nil {
		return fmt.Errorf("fixed OpenSSH ancestor %q ownership checker is required", path)
	}
	owned, err := ownershipChecker(info)
	if err != nil {
		return fmt.Errorf("inspect fixed OpenSSH ancestor %q ownership: %w", path, err)
	}
	if !owned {
		return fmt.Errorf("fixed OpenSSH ancestor %q must be owned by root", path)
	}
	return nil
}

func fixedPathAncestors(path string) []string {
	directory := filepath.Dir(path)
	result := make([]string, 0, 8)
	for {
		result = append(result, directory)
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	slices.Reverse(result)
	return result
}
