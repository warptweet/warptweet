//go:build darwin

package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func productionClientAssetDependencies() (clientAssetDependencies, error) {
	return clientAssetDependencies{
		layout:                 darwinProductionClientStateLayout(),
		resolveServiceIdentity: lookupDarwinClientServiceIdentity,
		inspectMetadata:        inspectDarwinClientFileMetadata,
	}, nil
}

func productionClientStateLayout() clientStateLayout {
	return darwinProductionClientStateLayout()
}

func lookupDarwinClientServiceIdentity(userName, groupName string) (clientServiceIdentity, error) {
	if userName == "" || groupName == "" {
		return clientServiceIdentity{}, errors.New("client service user and group names are required")
	}
	account, err := user.Lookup(userName)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service identity %q is not provisioned: %w",
			userName,
			err,
		)
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service group %q is not provisioned: %w",
			groupName,
			err,
		)
	}
	uid64, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf("parse client service UID: %w", err)
	}
	gid64, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf("parse client service GID: %w", err)
	}
	groupGID64, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf("parse client service group GID: %w", err)
	}
	if uid64 == 0 || gid64 == 0 {
		return clientServiceIdentity{}, errors.New("client service UID and primary GID must be nonzero")
	}
	if gid64 != groupGID64 {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service primary GID is %d but group %q has GID %d",
			gid64,
			groupName,
			groupGID64,
		)
	}
	if account.HomeDir != expectedDarwinClientServiceHome {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service home is %q, want %q",
			account.HomeDir,
			expectedDarwinClientServiceHome,
		)
	}
	shell, err := darwinUserShell(userName)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf("verify client service shell: %w", err)
	}
	if shell != expectedDarwinClientServiceShell {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service shell is %q, want %q",
			shell,
			expectedDarwinClientServiceShell,
		)
	}
	return clientServiceIdentity{uid: uint32(uid64), gid: uint32(gid64)}, nil
}

func darwinUserShell(userName string) (string, error) {
	if userName == "" || strings.ContainsAny(userName, "/\\:") {
		return "", fmt.Errorf("service user name is invalid")
	}
	if _, err := user.Lookup(userName); err != nil {
		return "", err
	}
	output, err := exec.Command("/usr/bin/dscl", ".", "-read", "/Users/"+userName, "UserShell").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return "", fmt.Errorf("dscl UserShell is empty")
	}
	return fields[len(fields)-1], nil
}

func inspectDarwinClientFileMetadata(
	_ string,
	file *os.File,
	info os.FileInfo,
) (clientFileMetadata, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return clientFileMetadata{}, errors.New("file metadata does not contain Darwin stat data")
	}
	hasExtendedACL, err := darwinFileHasExtendedACL(file)
	if err != nil {
		return clientFileMetadata{}, fmt.Errorf("inspect Darwin extended ACL: %w", err)
	}
	return clientFileMetadata{
		uid:           status.Uid,
		gid:           status.Gid,
		linkCount:     uint64(status.Nlink),
		hasAccessACL:  hasExtendedACL,
		hasDefaultACL: false,
	}, nil
}
