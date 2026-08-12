//go:build linux

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	clientAccessACLName                  = "system.posix_acl_access"
	clientDefaultACLName                 = "system.posix_acl_default"
	maxClientAccountDatabaseBytes        = 4 << 20
	productionClientPasswdPath           = "/etc/passwd"
	productionClientGroupPath            = "/etc/group"
	clientAccountValidationUID    uint32 = 1
	clientAccountValidationGID    uint32 = 1
)

func productionClientAssetDependencies() (clientAssetDependencies, error) {
	return clientAssetDependencies{
		layout:                 linuxProductionClientStateLayout(),
		resolveServiceIdentity: lookupClientServiceIdentity,
		inspectMetadata:        inspectLinuxClientFileMetadata,
	}, nil
}

func productionClientStateLayout() clientStateLayout {
	return linuxProductionClientStateLayout()
}

func lookupClientServiceIdentity(userName, groupName string) (clientServiceIdentity, error) {
	dependencies := clientAssetDependencies{
		layout:          linuxProductionClientStateLayout(),
		inspectMetadata: inspectLinuxClientFileMetadata,
	}
	validationIdentity := clientServiceIdentity{
		uid: clientAccountValidationUID,
		gid: clientAccountValidationGID,
	}
	passwd, err := openClientStateFile(
		dependencies,
		validationIdentity,
		productionClientPasswdPath,
		clientAccountDatabasePolicy("client passwd database"),
	)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	defer passwd.file.Close()
	group, err := openClientStateFile(
		dependencies,
		validationIdentity,
		productionClientGroupPath,
		clientAccountDatabasePolicy("client group database"),
	)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	defer group.file.Close()

	passwdData, err := readBoundedClientStateFile(
		passwd.file,
		maxClientAccountDatabaseBytes,
		"client passwd database",
	)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	groupData, err := readBoundedClientStateFile(
		group.file,
		maxClientAccountDatabaseBytes,
		"client group database",
	)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	verifiedPasswd, err := verifyOpenedClientStateFile(dependencies, validationIdentity, passwd)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	defer verifiedPasswd.file.Close()
	verifiedGroup, err := verifyOpenedClientStateFile(dependencies, validationIdentity, group)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	defer verifiedGroup.file.Close()
	verifiedPasswdData, err := readBoundedClientStateFile(
		verifiedPasswd.file,
		maxClientAccountDatabaseBytes,
		"client passwd database",
	)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	verifiedGroupData, err := readBoundedClientStateFile(
		verifiedGroup.file,
		maxClientAccountDatabaseBytes,
		"client group database",
	)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	if !bytes.Equal(passwdData, verifiedPasswdData) || !bytes.Equal(groupData, verifiedGroupData) {
		return clientServiceIdentity{}, errors.New(
			"client account databases changed during fixed-layout validation",
		)
	}
	return validateClientServiceIdentityData(userName, groupName, passwdData, groupData)
}

func clientAccountDatabasePolicy(description string) clientNodePolicy {
	return clientNodePolicy{
		description: description,
		mode:        0o644,
		group:       clientNodeRootGroup,
		minimumSize: 1,
		maximumSize: maxClientAccountDatabaseBytes,
	}
}

func inspectLinuxClientFileMetadata(
	_ string,
	file *os.File,
	info os.FileInfo,
) (clientFileMetadata, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return clientFileMetadata{}, errors.New("file metadata does not contain Linux stat data")
	}
	accessACL, err := linuxClientFileHasXattr(file, clientAccessACLName)
	if err != nil {
		return clientFileMetadata{}, fmt.Errorf("inspect access ACL: %w", err)
	}
	defaultACL, err := linuxClientFileHasXattr(file, clientDefaultACLName)
	if err != nil {
		return clientFileMetadata{}, fmt.Errorf("inspect default ACL: %w", err)
	}
	return clientFileMetadata{
		uid:           status.Uid,
		gid:           status.Gid,
		linkCount:     uint64(status.Nlink),
		hasAccessACL:  accessACL,
		hasDefaultACL: defaultACL,
	}, nil
}

func linuxClientFileHasXattr(file *os.File, name string) (bool, error) {
	if file == nil {
		return false, errors.New("file is nil")
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return false, err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FGETXATTR,
		file.Fd(),
		uintptr(unsafe.Pointer(namePointer)),
		0,
		0,
		0,
		0,
	)
	switch errno {
	case 0:
		return true, nil
	case syscall.ENODATA:
		return false, nil
	default:
		return false, errno
	}
}
