//go:build linux

package engine

import (
	"crypto/sha256"
	"fmt"
)

var serverAccountDatabasePolicy = serverAssetPolicy{
	maximumBytes: maxServerAccountDatabaseBytes,
	execution:    executionForbidden,
	forbidden:    0o022,
}

var serverShadowDatabasePolicy = serverAssetPolicy{
	maximumBytes: maxServerAccountDatabaseBytes,
	execution:    executionForbidden,
	// The shadow group may read /etc/shadow on common Linux systems, but no
	// group write and no world access are acceptable.
	forbidden: 0o027,
}

func inspectProductionServerAccounts(dedicatedUser string) (serverAccountEvidence, error) {
	etcAnchor, err := snapshotServerAncestor("/etc", requireProductionRootOwner)
	if err != nil {
		return serverAccountEvidence{}, fmt.Errorf("inspect server account database ancestor: %w", err)
	}
	defer etcAnchor.file.Close()

	passwdData, passwdHash, err := readProductionAccountDatabase(
		"/etc/passwd",
		"passwd",
		serverAccountDatabasePolicy,
	)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	defer clear(passwdData)
	groupData, groupHash, err := readProductionAccountDatabase(
		"/etc/group",
		"group",
		serverAccountDatabasePolicy,
	)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	defer clear(groupData)
	shadowData, shadowHash, err := readProductionAccountDatabase(
		"/etc/shadow",
		"shadow",
		serverShadowDatabasePolicy,
	)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	defer clear(shadowData)

	evidence, err := inspectServerAccountData(dedicatedUser, passwdData, groupData, shadowData)
	if err != nil {
		return serverAccountEvidence{}, fmt.Errorf("validate server Unix accounts: %w", err)
	}
	passwdAfter, passwdHashAfter, err := readProductionAccountDatabase("/etc/passwd", "passwd", serverAccountDatabasePolicy)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	clear(passwdAfter)
	groupAfter, groupHashAfter, err := readProductionAccountDatabase("/etc/group", "group", serverAccountDatabasePolicy)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	clear(groupAfter)
	shadowAfter, shadowHashAfter, err := readProductionAccountDatabase("/etc/shadow", "shadow", serverShadowDatabasePolicy)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	clear(shadowAfter)
	if passwdHashAfter != passwdHash || groupHashAfter != groupHash || shadowHashAfter != shadowHash {
		return serverAccountEvidence{}, fmt.Errorf("validate server Unix accounts: account database hash changed unexpectedly")
	}
	if err := verifyHeldServerAncestor(etcAnchor, requireProductionRootOwner); err != nil {
		return serverAccountEvidence{}, fmt.Errorf("revalidate server account database ancestor: %w", err)
	}
	return evidence, nil
}

func readProductionAccountDatabase(
	path,
	description string,
	policy serverAssetPolicy,
) ([]byte, [sha256.Size]byte, error) {
	snapshot, err := snapshotServerAsset(
		path,
		"system "+description+" database",
		policy,
		requireProductionRootOwner,
	)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	defer snapshot.file.Close()
	digest := sha256.Sum256(snapshot.data)
	return snapshot.data, digest, nil
}
