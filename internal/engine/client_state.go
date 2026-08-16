package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/installlayout"
)

const maxClientIdentityBytes = 1 << 20

const (
	expectedClientServiceHome  = "/nonexistent"
	expectedClientServiceShell = "/usr/sbin/nologin"

	expectedDarwinClientServiceHome  = "/var/empty"
	expectedDarwinClientServiceShell = "/usr/bin/false"
)

type clientStateLayout struct {
	rootPath             string
	manifestPath         string
	identityDirectory    string
	identityPath         string
	trustDirectory       string
	knownHostsPath       string
	globalKnownHostsPath string
	serviceUser          string
	serviceGroup         string
	directoryPolicies    map[string]clientNodePolicy
}

type clientServiceIdentity struct {
	uid uint32
	gid uint32
}

type clientFileMetadata struct {
	uid           uint32
	gid           uint32
	linkCount     uint64
	hasAccessACL  bool
	hasDefaultACL bool
}

type clientAssetHooks struct {
	afterInitialOpen  func()
	beforeFinalVerify func()
}

type clientAssetDependencies struct {
	layout                 clientStateLayout
	resolveServiceIdentity func(string, string) (clientServiceIdentity, error)
	inspectMetadata        func(string, *os.File, os.FileInfo) (clientFileMetadata, error)
	hooks                  clientAssetHooks
}

type clientNodeGroup uint8

const (
	clientNodeRootGroup clientNodeGroup = iota
	clientNodeServiceGroup
)

type clientNodePolicy struct {
	description         string
	directory           bool
	mode                os.FileMode
	group               clientNodeGroup
	serviceOwned        bool
	minimumSize         int64
	maximumSize         int64
	allowRootAdminGroup bool
}

type openedClientFile struct {
	path     string
	file     *os.File
	info     os.FileInfo
	metadata clientFileMetadata
	policy   clientNodePolicy
}

func linuxProductionClientStateLayout() clientStateLayout {
	return clientStateLayout{
		rootPath:             string(os.PathSeparator),
		manifestPath:         installlayout.ClientManifestPath,
		identityDirectory:    installlayout.ClientIdentityDirectory,
		identityPath:         installlayout.ClientIdentityPath,
		trustDirectory:       installlayout.ClientTrustDirectory,
		knownHostsPath:       installlayout.ClientKnownHostsPath,
		globalKnownHostsPath: installlayout.ClientGlobalKnownHostsPath,
		serviceUser:          installlayout.ClientServiceUser,
		serviceGroup:         installlayout.ClientServiceGroup,
		directoryPolicies: map[string]clientNodePolicy{
			string(os.PathSeparator): {
				description: "filesystem root",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			"/etc": {
				description: "/etc client-state ancestor",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			"/etc/warptweet": {
				description: "WarpTweet client-state directory",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			installlayout.ClientIdentityDirectory: {
				description: "client identity directory",
				directory:   true,
				mode:        0o750,
				group:       clientNodeServiceGroup,
			},
			installlayout.ClientTrustDirectory: {
				description: "client trust directory",
				directory:   true,
				mode:        0o750,
				group:       clientNodeServiceGroup,
			},
		},
	}
}

func darwinProductionClientStateLayout() clientStateLayout {
	return clientStateLayout{
		rootPath:             string(os.PathSeparator),
		manifestPath:         installlayout.DarwinClientManifestPath,
		identityDirectory:    installlayout.DarwinClientIdentityDirectory,
		identityPath:         installlayout.DarwinClientIdentityPath,
		trustDirectory:       installlayout.DarwinClientTrustDirectory,
		knownHostsPath:       installlayout.DarwinClientKnownHostsPath,
		globalKnownHostsPath: installlayout.DarwinClientGlobalKnownHostsPath,
		serviceUser:          installlayout.DarwinClientServiceUser,
		serviceGroup:         installlayout.DarwinClientServiceGroup,
		directoryPolicies: map[string]clientNodePolicy{
			string(os.PathSeparator): {
				description: "filesystem root",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			"/Library": {
				description: "/Library client-state ancestor",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			"/Library/Application Support": {
				description:         "Application Support client-state ancestor",
				directory:           true,
				mode:                0o755,
				group:               clientNodeRootGroup,
				allowRootAdminGroup: true,
			},
			installlayout.DarwinApplicationSupportRoot: {
				description: "WarpTweet application support root",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			installlayout.DarwinClientStateRoot: {
				description: "WarpTweet client-state directory",
				directory:   true,
				mode:        0o755,
				group:       clientNodeRootGroup,
			},
			installlayout.DarwinClientIdentityDirectory: {
				description: "client identity directory",
				directory:   true,
				mode:        0o750,
				group:       clientNodeServiceGroup,
			},
			installlayout.DarwinClientTrustDirectory: {
				description: "client trust directory",
				directory:   true,
				mode:        0o750,
				group:       clientNodeServiceGroup,
			},
		},
	}
}

func manifestClientNodePolicy() clientNodePolicy {
	return clientNodePolicy{
		description: "client manifest",
		mode:        0o440,
		group:       clientNodeServiceGroup,
		minimumSize: 1,
		maximumSize: config.MaxConfigBytes,
	}
}

func identityClientNodePolicy() clientNodePolicy {
	return clientNodePolicy{
		description: "client identity file",
		// OpenSSH requires private keys without group/other bits.
		mode:         0o600,
		group:        clientNodeServiceGroup,
		serviceOwned: true,
		minimumSize:  1,
		maximumSize:  maxClientIdentityBytes,
	}
}

func knownHostsClientNodePolicy() clientNodePolicy {
	return clientNodePolicy{
		description: "client known-hosts file",
		mode:        0o440,
		group:       clientNodeServiceGroup,
		maximumSize: maxTrustFileBytes,
	}
}

func globalKnownHostsClientNodePolicy() clientNodePolicy {
	return clientNodePolicy{
		description: "client global known-hosts file",
		mode:        0o440,
		group:       clientNodeServiceGroup,
		maximumSize: maxTrustFileBytes,
	}
}

// LoadProductionClientManifest reads the one fixed client manifest through the
// protected client-state layout. Candidate manifests used by validation and
// rendering continue to use config.Load.
func LoadProductionClientManifest(path string) (config.Config, error) {
	layout := productionClientStateLayout()
	if path != layout.manifestPath {
		return config.Config{}, fmt.Errorf(
			"production client manifest path must be exactly %q",
			layout.manifestPath,
		)
	}
	dependencies, err := productionClientAssetDependencies()
	if err != nil {
		return config.Config{}, err
	}
	return loadProductionClientManifestWithDependencies(path, dependencies)
}

func loadProductionClientManifestWithDependencies(
	path string,
	dependencies clientAssetDependencies,
) (config.Config, error) {
	if path != dependencies.layout.manifestPath {
		return config.Config{}, fmt.Errorf(
			"production client manifest path must be exactly %q",
			dependencies.layout.manifestPath,
		)
	}
	identity, err := resolveClientServiceIdentity(dependencies)
	if err != nil {
		return config.Config{}, err
	}
	manifest, err := openClientStateFile(
		dependencies,
		identity,
		path,
		manifestClientNodePolicy(),
	)
	if err != nil {
		return config.Config{}, err
	}
	defer manifest.file.Close()

	contents, err := readBoundedClientStateFile(manifest.file, config.MaxConfigBytes, "client manifest")
	if err != nil {
		return config.Config{}, err
	}
	if dependencies.hooks.afterInitialOpen != nil {
		dependencies.hooks.afterInitialOpen()
	}
	if dependencies.hooks.beforeFinalVerify != nil {
		dependencies.hooks.beforeFinalVerify()
	}
	verified, err := verifyOpenedClientStateFile(dependencies, identity, manifest)
	if err != nil {
		return config.Config{}, err
	}
	defer verified.file.Close()
	verifiedContents, err := readBoundedClientStateFile(
		verified.file,
		config.MaxConfigBytes,
		"client manifest",
	)
	if err != nil {
		return config.Config{}, err
	}
	if !bytes.Equal(contents, verifiedContents) {
		return config.Config{}, errors.New("client manifest changed during fixed-layout validation")
	}
	manifestConfig, err := config.Decode(bytes.NewReader(contents))
	if err != nil {
		return config.Config{}, fmt.Errorf("load fixed client manifest %q: %w", path, err)
	}
	return manifestConfig, nil
}

func resolveClientServiceIdentity(
	dependencies clientAssetDependencies,
) (clientServiceIdentity, error) {
	if dependencies.resolveServiceIdentity == nil {
		return clientServiceIdentity{}, errors.New("client service identity resolver is required")
	}
	identity, err := dependencies.resolveServiceIdentity(
		dependencies.layout.serviceUser,
		dependencies.layout.serviceGroup,
	)
	if err != nil {
		return clientServiceIdentity{}, fmt.Errorf("resolve client service identity: %w", err)
	}
	if identity.uid == 0 || identity.gid == 0 {
		return clientServiceIdentity{}, errors.New("client service identity must use non-root UID and GID")
	}
	return identity, nil
}

func validateClientServiceIdentityData(
	userName,
	groupName string,
	passwdData,
	groupData []byte,
) (clientServiceIdentity, error) {
	if userName == "" || groupName == "" {
		return clientServiceIdentity{}, errors.New("client service user and group names are required")
	}
	passwdRecords, err := parseUnixPasswd(passwdData)
	if err != nil {
		return clientServiceIdentity{}, err
	}
	groupRecords, err := parseUnixGroup(groupData)
	if err != nil {
		return clientServiceIdentity{}, err
	}

	var account unixPasswdRecord
	accountCount := 0
	for _, record := range passwdRecords {
		if record.name == userName {
			account = record
			accountCount++
		}
	}
	if accountCount != 1 {
		return clientServiceIdentity{}, fmt.Errorf(
			"passwd contains %d entries for client service user %q, want exactly one",
			accountCount,
			userName,
		)
	}
	if account.uid == 0 || account.gid == 0 ||
		account.uid > math.MaxUint32 || account.gid > math.MaxUint32 {
		return clientServiceIdentity{}, errors.New(
			"client service UID and primary GID must be nonzero 32-bit Unix IDs",
		)
	}
	if !account.shadowDelegated {
		return clientServiceIdentity{}, errors.New(
			"client service passwd password field must delegate to shadow with x",
		)
	}
	if account.home != expectedClientServiceHome {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service home is %q, want %q",
			account.home,
			expectedClientServiceHome,
		)
	}
	if account.shell != expectedClientServiceShell {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service shell is %q, want %q",
			account.shell,
			expectedClientServiceShell,
		)
	}
	for _, record := range passwdRecords {
		if record.name == userName {
			continue
		}
		if record.uid == account.uid {
			return clientServiceIdentity{}, fmt.Errorf(
				"client service UID %d is also used by account %q",
				account.uid,
				record.name,
			)
		}
		if record.gid == account.gid {
			return clientServiceIdentity{}, fmt.Errorf(
				"client service primary GID %d is also used by account %q",
				account.gid,
				record.name,
			)
		}
	}

	var primaryGroup unixGroupRecord
	primaryGroupCount := 0
	for _, group := range groupRecords {
		if group.name == groupName {
			primaryGroup = group
			primaryGroupCount++
		}
		for _, member := range group.members {
			if member == userName {
				return clientServiceIdentity{}, fmt.Errorf(
					"client service user is listed as a supplementary member of group %q",
					group.name,
				)
			}
		}
	}
	if primaryGroupCount != 1 {
		return clientServiceIdentity{}, fmt.Errorf(
			"group contains %d entries for client service group %q, want exactly one",
			primaryGroupCount,
			groupName,
		)
	}
	if primaryGroup.gid != account.gid {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service primary GID is %d but group %q has GID %d",
			account.gid,
			groupName,
			primaryGroup.gid,
		)
	}
	if !primaryGroup.shadowDelegated {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service group %q password field must delegate with x",
			groupName,
		)
	}
	if len(primaryGroup.members) != 0 {
		return clientServiceIdentity{}, fmt.Errorf(
			"client service group %q must not list supplementary members",
			groupName,
		)
	}
	for _, group := range groupRecords {
		if group.name != groupName && group.gid == account.gid {
			return clientServiceIdentity{}, fmt.Errorf(
				"client service GID %d is also used by group %q",
				account.gid,
				group.name,
			)
		}
	}

	return clientServiceIdentity{uid: uint32(account.uid), gid: uint32(account.gid)}, nil
}

func openClientStateFile(
	dependencies clientAssetDependencies,
	identity clientServiceIdentity,
	path string,
	policy clientNodePolicy,
) (*openedClientFile, error) {
	if dependencies.inspectMetadata == nil {
		return nil, errors.New("client-state metadata inspector is required")
	}
	rootPath, relative, err := relativeClientStatePath(dependencies.layout.rootPath, path)
	if err != nil {
		return nil, err
	}
	components := splitClientStatePath(relative)
	if len(components) == 0 {
		return nil, fmt.Errorf("%s path must name a file below the client-state root", policy.description)
	}

	current, err := openClientStateRoot(dependencies, identity, rootPath)
	if err != nil {
		return nil, err
	}
	currentPath := rootPath
	for _, component := range components[:len(components)-1] {
		nextPath := filepath.Join(currentPath, component)
		directoryPolicy, ok := dependencies.layout.directoryPolicies[nextPath]
		if !ok {
			_ = current.Close()
			return nil, fmt.Errorf("client-state directory %q is outside the fixed layout", nextPath)
		}
		next, openErr := openClientStateDirectory(
			dependencies,
			identity,
			current,
			component,
			nextPath,
			directoryPolicy,
		)
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		if closeErr := current.Close(); closeErr != nil {
			_ = next.Close()
			return nil, fmt.Errorf("close client-state ancestor %q: %w", currentPath, closeErr)
		}
		current = next
		currentPath = nextPath
	}

	name := components[len(components)-1]
	before, err := current.Lstat(name)
	if err != nil {
		_ = current.Close()
		return nil, fmt.Errorf("inspect %s: %w", policy.description, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		_ = current.Close()
		return nil, fmt.Errorf("%s must be a non-symlink regular file", policy.description)
	}
	file, err := current.Open(name)
	if err != nil {
		_ = current.Close()
		return nil, fmt.Errorf("open %s: %w", policy.description, err)
	}
	opened, openedErr := file.Stat()
	after, afterErr := current.Lstat(name)
	closeErr := current.Close()
	if openedErr != nil || afterErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("reinspect %s while opening it", policy.description)
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("close parent of %s: %w", policy.description, closeErr)
	}
	if after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed while it was opened", policy.description)
	}
	metadata, err := dependencies.inspectMetadata(path, file, opened)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect %s Linux metadata: %w", policy.description, err)
	}
	if err := validateClientNode(opened, metadata, policy, identity); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &openedClientFile{
		path:     path,
		file:     file,
		info:     opened,
		metadata: metadata,
		policy:   policy,
	}, nil
}

func openClientStateRoot(
	dependencies clientAssetDependencies,
	identity clientServiceIdentity,
	rootPath string,
) (*os.Root, error) {
	policy, ok := dependencies.layout.directoryPolicies[rootPath]
	if !ok {
		return nil, fmt.Errorf("client-state root %q has no fixed policy", rootPath)
	}
	before, err := os.Lstat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("inspect client-state root: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("client-state root must be a non-symlink directory")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open client-state root: %w", err)
	}
	rootFile, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open client-state root descriptor: %w", err)
	}
	opened, openedErr := rootFile.Stat()
	after, afterErr := os.Lstat(rootPath)
	if openedErr != nil || afterErr != nil {
		_ = rootFile.Close()
		_ = root.Close()
		return nil, errors.New("reinspect client-state root while opening it")
	}
	if after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(before, after) {
		_ = rootFile.Close()
		_ = root.Close()
		return nil, errors.New("client-state root changed while it was opened")
	}
	metadata, err := dependencies.inspectMetadata(rootPath, rootFile, opened)
	if err != nil {
		_ = rootFile.Close()
		_ = root.Close()
		return nil, fmt.Errorf("inspect client-state root Linux metadata: %w", err)
	}
	if err := rootFile.Close(); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("close client-state root descriptor: %w", err)
	}
	if err := validateClientNode(opened, metadata, policy, identity); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func openClientStateDirectory(
	dependencies clientAssetDependencies,
	identity clientServiceIdentity,
	parent *os.Root,
	name string,
	path string,
	policy clientNodePolicy,
) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", policy.description, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, fmt.Errorf("%s must be a non-symlink directory", policy.description)
	}
	directory, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", policy.description, err)
	}
	directoryFile, err := directory.Open(".")
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("open %s descriptor: %w", policy.description, err)
	}
	opened, openedErr := directoryFile.Stat()
	after, afterErr := parent.Lstat(name)
	if openedErr != nil || afterErr != nil {
		_ = directoryFile.Close()
		_ = directory.Close()
		return nil, fmt.Errorf("reinspect %s while opening it", policy.description)
	}
	if after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(before, after) {
		_ = directoryFile.Close()
		_ = directory.Close()
		return nil, fmt.Errorf("%s changed while it was opened", policy.description)
	}
	metadata, err := dependencies.inspectMetadata(path, directoryFile, opened)
	if err != nil {
		_ = directoryFile.Close()
		_ = directory.Close()
		return nil, fmt.Errorf("inspect %s Linux metadata: %w", policy.description, err)
	}
	if err := directoryFile.Close(); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("close %s descriptor: %w", policy.description, err)
	}
	if err := validateClientNode(opened, metadata, policy, identity); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func validateClientNode(
	info os.FileInfo,
	metadata clientFileMetadata,
	policy clientNodePolicy,
	identity clientServiceIdentity,
) error {
	if policy.directory {
		if !info.IsDir() {
			return fmt.Errorf("%s must be a directory", policy.description)
		}
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", policy.description)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%s contains a forbidden special mode", policy.description)
	}
	if info.Mode().Perm() != policy.mode.Perm() {
		return fmt.Errorf(
			"%s permissions are %04o, want exactly %04o",
			policy.description,
			info.Mode().Perm(),
			policy.mode.Perm(),
		)
	}
	expectedGID := uint32(0)
	if policy.group == clientNodeServiceGroup {
		expectedGID = identity.gid
	}
	expectedUID := uint32(0)
	if policy.serviceOwned {
		expectedUID = identity.uid
	}
	if metadata.uid != expectedUID || metadata.gid != expectedGID {
		// macOS keeps /Library/Application Support as root:admin (gid 80).
		if !(runtime.GOOS == "darwin" &&
			policy.directory &&
			policy.allowRootAdminGroup &&
			policy.group == clientNodeRootGroup &&
			metadata.uid == 0 &&
			metadata.gid == 80) {
			return fmt.Errorf(
				"%s ownership is %d:%d, want %d:%d",
				policy.description,
				metadata.uid,
				metadata.gid,
				expectedUID,
				expectedGID,
			)
		}
	}
	if metadata.hasAccessACL || metadata.hasDefaultACL {
		return fmt.Errorf("%s must not have a POSIX ACL", policy.description)
	}
	if !policy.directory && metadata.linkCount != 1 {
		return fmt.Errorf("%s link count is %d, want exactly 1", policy.description, metadata.linkCount)
	}
	if !policy.directory && (info.Size() < policy.minimumSize || info.Size() > policy.maximumSize) {
		return fmt.Errorf(
			"%s size is %d, want between %d and %d bytes",
			policy.description,
			info.Size(),
			policy.minimumSize,
			policy.maximumSize,
		)
	}
	return nil
}

func verifyOpenedClientStateFile(
	dependencies clientAssetDependencies,
	identity clientServiceIdentity,
	initial *openedClientFile,
) (*openedClientFile, error) {
	current, err := openClientStateFile(dependencies, identity, initial.path, initial.policy)
	if err != nil {
		return nil, fmt.Errorf("reverify %s: %w", initial.policy.description, err)
	}
	if !os.SameFile(initial.info, current.info) ||
		initial.info.Mode() != current.info.Mode() ||
		initial.info.Size() != current.info.Size() ||
		!initial.info.ModTime().Equal(current.info.ModTime()) ||
		initial.metadata != current.metadata {
		_ = current.file.Close()
		return nil, fmt.Errorf("%s changed during fixed-layout validation", initial.policy.description)
	}
	return current, nil
}

func relativeClientStatePath(rootPath, path string) (string, string, error) {
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return "", "", errors.New("client-state root must be a clean absolute path")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", errors.New("client-state file must use a clean absolute path")
	}
	relative, err := filepath.Rel(rootPath, path)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", "", errors.New("client-state file must be below the fixed client-state root")
	}
	return rootPath, relative, nil
}

func splitClientStatePath(relative string) []string {
	result := make([]string, 0, 8)
	for relative != "." {
		directory, name := filepath.Split(relative)
		if name != "" {
			result = append(result, name)
		}
		relative = filepath.Clean(directory)
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func readBoundedClientStateFile(file *os.File, maximum int64, description string) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s: %w", description, err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", description, err)
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", description, maximum)
	}
	return contents, nil
}
