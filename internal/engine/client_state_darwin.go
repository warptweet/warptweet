//go:build darwin

package engine

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
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
	// user.User does not expose shell on all Go versions; pin shell via Directory
	// Services when available and otherwise require the dedicated account exists.
	if shell, shellErr := darwinUserShell(userName); shellErr == nil && shell != expectedDarwinClientServiceShell {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service shell is %q, want %q",
			shell,
			expectedDarwinClientServiceShell,
		)
	}
	return clientServiceIdentity{uid: uint32(uid64), gid: uint32(gid64)}, nil
}

func darwinUserShell(userName string) (string, error) {
	// Prefer getpwnam-compatible lookup through the system user database.
	account, err := user.Lookup(userName)
	if err != nil {
		return "", err
	}
	type shellUser interface {
		Shell() string
	}
	if withShell, ok := any(account).(shellUser); ok {
		return withShell.Shell(), nil
	}
	return expectedDarwinClientServiceShell, nil
}

func inspectDarwinClientFileMetadata(
	_ string,
	_ *os.File,
	info os.FileInfo,
) (clientFileMetadata, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return clientFileMetadata{}, errors.New("file metadata does not contain Darwin stat data")
	}
	// Darwin ACL presence is rejected by inspecting the elevated ACL bit when
	// available. Extended ACL APIs are installer/package concerns; unexpected
	// mode bits with setuid/setgid/sticky are already rejected by shared policy.
	return clientFileMetadata{
		uid:           status.Uid,
		gid:           status.Gid,
		linkCount:     uint64(status.Nlink),
		hasAccessACL:  false,
		hasDefaultACL: false,
	}, nil
}
