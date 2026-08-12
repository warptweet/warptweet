package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/opensshsource"
	"warptweet.com/warptweet/internal/opensslsource"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
	"warptweet.com/warptweet/internal/sshwire"
)

const (
	maxServerExecutableBytes = 64 << 20
	maxBundleManifestBytes   = 1 << 20
	maxSourceReceiptBytes    = 64 << 10
	maxServerLicenseBytes    = 1 << 20
	maxInstalledConfigBytes  = 1 << 20
	maxServerHostKeyBytes    = 64 << 10
	maxServerCommandOutput   = 1 << 20

	expectedOpenSSHSysconfDir = "/opt/warptweet/etc/openssh"
	expectedServerPIDFile     = "/run/warptweet/server/warptweet-sshd.pid"
)

var (
	serverExecutablePolicy = serverAssetPolicy{
		maximumBytes: maxServerExecutableBytes,
		execution:    executionRequired,
		forbidden:    0o022,
	}
	bundleMemberPolicy = serverAssetPolicy{
		maximumBytes: maxServerExecutableBytes,
		execution:    executionAllowed,
		forbidden:    0o022,
	}
	bundleManifestPolicy = serverAssetPolicy{
		maximumBytes: maxBundleManifestBytes,
		execution:    executionForbidden,
		forbidden:    0o022,
	}
	sourceReceiptPolicy = serverAssetPolicy{
		maximumBytes: maxSourceReceiptBytes,
		execution:    executionForbidden,
		forbidden:    0o022,
	}
	serverLicensePolicy = serverAssetPolicy{
		maximumBytes: maxServerLicenseBytes,
		execution:    executionForbidden,
		forbidden:    0o022,
	}
	installedConfigPolicy = serverAssetPolicy{
		maximumBytes: maxInstalledConfigBytes,
		execution:    executionForbidden,
		forbidden:    0o022,
	}
	serverHostKeyPolicy = serverAssetPolicy{
		maximumBytes: maxServerHostKeyBytes,
		execution:    executionForbidden,
		forbidden:    0o077,
	}
	authorizedKeysPolicy = serverAssetPolicy{
		maximumBytes: server.MaxAuthorizedKeysBytes,
		execution:    executionForbidden,
		forbidden:    0o022,
	}
)

// ServerPreflightReport contains only non-secret facts proven about the fixed
// installed OpenSSH server and its effective WarpTweet policy.
type ServerPreflightReport struct {
	SSHDPath                    string
	SSHDBinarySHA256            string
	OpenSSHBundleManifestSHA256 string
	EngineVersion               string
	Profile                     string
	OpenSSLVersion              string
	OpenSSLVersionText          string
	OpenSSLLinkage              string
	ExecutableFormat            string
	StaticLibcryptoSHA256       string
	HostPublicKeySHA256         string
	AuthorizedKeyCount          int
}

// PreflightServer validates the fixed production server installation. Callers
// cannot substitute engine, helper, receipt, policy, or key paths.
func PreflightServer(ctx context.Context, config server.Config) (ServerPreflightReport, error) {
	return preflightServer(ctx, config, serverPreflightDependencies{
		layout:                productionServerPreflightLayout(),
		runner:                execServerCommandRunner{},
		inspector:             productionExecutableInspector(),
		environment:           os.Environ,
		platform:              runtime.GOOS,
		architecture:          productionServerArchitecture(runtime.GOARCH),
		ownerValidator:        requireProductionRootOwner,
		privsepOwnerValidator: requireProductionRootGroupOwner,
		accountInspector:      inspectProductionServerAccounts,
	})
}

type serverPreflightLayout struct {
	stageRoot          string
	sshPath            string
	sshdPath           string
	sshdAuthPath       string
	sshdSessionPath    string
	sshKeygenPath      string
	bundleManifestPath string
	sourceReceiptPath  string
	openSSLReceiptPath string
	openSSHLicensePath string
	openSSLLicensePath string
	serverConfigPath   string
	hostKeyPath        string
	authorizedKeysPath string
	privsepDirectory   string
}

func productionServerPreflightLayout() serverPreflightLayout {
	return serverPreflightLayout{
		stageRoot:          string(filepath.Separator),
		sshPath:            installlayout.SSHPath,
		sshdPath:           installlayout.SSHDPath,
		sshdAuthPath:       installlayout.SSHDAuthPath,
		sshdSessionPath:    installlayout.SSHDSessionPath,
		sshKeygenPath:      installlayout.SSHKeygenPath,
		bundleManifestPath: installlayout.OpenSSHBundleManifestPath,
		sourceReceiptPath:  installlayout.OpenSSHSourceReceiptPath,
		openSSLReceiptPath: installlayout.OpenSSLSourceReceiptPath,
		openSSHLicensePath: installlayout.OpenSSHLicensePath,
		openSSLLicensePath: installlayout.OpenSSLLicensePath,
		serverConfigPath:   installlayout.ServerConfigPath,
		hostKeyPath:        installlayout.ServerHostKeyPath,
		privsepDirectory:   installlayout.PrivsepDirectory,
	}
}

type serverCommandResult struct {
	stdout []byte
	stderr []byte
}

type serverCommandRunner interface {
	Run(context.Context, string, []string, ...string) (serverCommandResult, error)
}

type serverOwnerValidator func(string, os.FileInfo) error

type serverPreflightDependencies struct {
	layout                serverPreflightLayout
	runner                serverCommandRunner
	inspector             executableInspector
	environment           func() []string
	platform              string
	architecture          string
	ownerValidator        serverOwnerValidator
	privsepOwnerValidator serverOwnerValidator
	accountInspector      serverAccountInspector
}

type executionPolicy uint8

const (
	executionAllowed executionPolicy = iota
	executionRequired
	executionForbidden
)

type serverAssetPolicy struct {
	maximumBytes int64
	execution    executionPolicy
	forbidden    os.FileMode
}

type serverAssetSnapshot struct {
	data   []byte
	sha256 string
	info   os.FileInfo
	policy serverAssetPolicy
	file   *os.File
}

// serverAssetMetadataSnapshot intentionally has no byte slice or digest. The
// controller must never read or retain a host private key.
type serverAssetMetadataSnapshot struct {
	info   os.FileInfo
	policy serverAssetPolicy
	file   *os.File
}

type bundleManifestEntry struct {
	path   string
	sha256 string
}

type serverExecutableLinkageEvidence struct {
	path   string
	report executableLinkageReport
}

type serverSourceReceiptEvidence struct {
	staticLibcryptoSHA256 string
}

func preflightServer(
	ctx context.Context,
	config server.Config,
	dependencies serverPreflightDependencies,
) (ServerPreflightReport, error) {
	if err := server.Validate(config); err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: validate policy: %w", err)
	}
	if ctx == nil {
		return ServerPreflightReport{}, errors.New("preflight server: context is nil")
	}
	if dependencies.runner == nil {
		return ServerPreflightReport{}, errors.New("preflight server: command runner is nil")
	}
	if dependencies.inspector == nil {
		return ServerPreflightReport{}, errors.New("preflight server: executable inspector is nil")
	}
	if dependencies.environment == nil {
		return ServerPreflightReport{}, errors.New("preflight server: environment provider is nil")
	}
	if err := validateServerBuildPlatform(dependencies.platform, dependencies.architecture); err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}
	environment := sanitizedClientEnvironment(dependencies.environment())
	if dependencies.ownerValidator == nil {
		return ServerPreflightReport{}, errors.New("preflight server: owner validator is nil")
	}
	if dependencies.privsepOwnerValidator == nil {
		return ServerPreflightReport{}, errors.New("preflight server: privilege-separation owner validator is nil")
	}
	if dependencies.accountInspector == nil {
		return ServerPreflightReport{}, errors.New("preflight server: account inspector is nil")
	}
	if dependencies.layout.authorizedKeysPath == "" {
		dependencies.layout.authorizedKeysPath = physicalPathForLogical(
			dependencies.layout.stageRoot,
			config.AuthorizedKeysPath,
		)
	}
	if err := validateServerPreflightLayout(dependencies.layout); err != nil {
		return ServerPreflightReport{}, err
	}
	ancestors, err := snapshotServerAncestors(dependencies.layout, dependencies.ownerValidator)
	if err != nil {
		return ServerPreflightReport{}, err
	}
	defer ancestors.Close()
	if err := ancestors.RequireDirectoryMode(
		dependencies.layout.privsepDirectory,
		0o755,
		dependencies.privsepOwnerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	accountEvidence, err := dependencies.accountInspector(config.DedicatedUser)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: validate Unix account contract: %w", err)
	}

	selectedProfile, err := profile.Lookup(config.ProfileID)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: load profile: %w", err)
	}

	tracked := make(map[string]serverAssetSnapshot)
	var hostKeyMetadata serverAssetMetadataSnapshot
	defer closeServerPreflightSnapshots(tracked, &hostKeyMetadata)
	initialAssets := []struct {
		path        string
		description string
		policy      serverAssetPolicy
	}{
		{dependencies.layout.sshdPath, "sshd executable", serverExecutablePolicy},
		{dependencies.layout.sshdAuthPath, "sshd-auth executable", serverExecutablePolicy},
		{dependencies.layout.sshdSessionPath, "sshd-session executable", serverExecutablePolicy},
		{dependencies.layout.sshKeygenPath, "ssh-keygen executable", serverExecutablePolicy},
		{dependencies.layout.sshPath, "ssh executable", serverExecutablePolicy},
		{dependencies.layout.bundleManifestPath, "OpenSSH bundle manifest", bundleManifestPolicy},
		{dependencies.layout.sourceReceiptPath, "OpenSSH source receipt", sourceReceiptPolicy},
		{dependencies.layout.openSSLReceiptPath, "OpenSSL source receipt", sourceReceiptPolicy},
		{dependencies.layout.openSSHLicensePath, "OpenSSH license", serverLicensePolicy},
		{dependencies.layout.openSSLLicensePath, "OpenSSL license", serverLicensePolicy},
		{dependencies.layout.serverConfigPath, "rendered sshd configuration", installedConfigPolicy},
	}
	for _, asset := range initialAssets {
		snapshot, snapshotErr := snapshotServerAsset(
			asset.path,
			asset.description,
			asset.policy,
			dependencies.ownerValidator,
		)
		if snapshotErr != nil {
			return ServerPreflightReport{}, snapshotErr
		}
		tracked[asset.path] = snapshot
	}
	hostKeyMetadata, err = snapshotServerAssetMetadata(
		dependencies.layout.hostKeyPath,
		"server host private key",
		serverHostKeyPolicy,
		dependencies.ownerValidator,
	)
	if err != nil {
		return ServerPreflightReport{}, err
	}
	authorizedKeysSnapshot, err := snapshotServerAsset(
		dependencies.layout.authorizedKeysPath,
		"managed authorized_keys",
		authorizedKeysPolicy,
		dependencies.ownerValidator,
	)
	if err != nil {
		return ServerPreflightReport{}, err
	}
	tracked[dependencies.layout.authorizedKeysPath] = authorizedKeysSnapshot
	if err := ancestors.Verify(dependencies.ownerValidator); err != nil {
		return ServerPreflightReport{}, err
	}

	sshdSnapshot := tracked[dependencies.layout.sshdPath]
	bundleSnapshot := tracked[dependencies.layout.bundleManifestPath]
	receiptSnapshot := tracked[dependencies.layout.sourceReceiptPath]
	openSSLReceiptSnapshot := tracked[dependencies.layout.openSSLReceiptPath]
	configSnapshot := tracked[dependencies.layout.serverConfigPath]

	if bundleSnapshot.sha256 != config.OpenSSHBundleManifestSHA256 {
		return ServerPreflightReport{}, fmt.Errorf(
			"preflight server: OpenSSH bundle manifest SHA-256 is %s, want %s",
			bundleSnapshot.sha256,
			config.OpenSSHBundleManifestSHA256,
		)
	}
	if sshdSnapshot.sha256 != config.SSHDBinarySHA256 {
		return ServerPreflightReport{}, fmt.Errorf(
			"preflight server: sshd SHA-256 is %s, want %s",
			sshdSnapshot.sha256,
			config.SSHDBinarySHA256,
		)
	}

	manifestEntries, err := parseBundleManifest(bundleSnapshot.data)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}
	requiredManifestPaths, err := requiredServerManifestPaths(dependencies.layout)
	if err != nil {
		return ServerPreflightReport{}, err
	}
	manifestDescriptions := make(map[string]string, len(requiredManifestPaths))
	for description, requiredPath := range requiredManifestPaths {
		manifestDescriptions[requiredPath] = description
	}
	manifestEntryPaths := make(map[string]struct{}, len(manifestEntries))
	for _, entry := range manifestEntries {
		if _, required := manifestDescriptions[entry.path]; !required {
			return ServerPreflightReport{}, fmt.Errorf(
				"preflight server: bundle manifest contains unexpected path %q",
				entry.path,
			)
		}
		manifestEntryPaths[entry.path] = struct{}{}
	}
	for description, requiredPath := range requiredManifestPaths {
		if _, present := manifestEntryPaths[requiredPath]; !present {
			return ServerPreflightReport{}, fmt.Errorf(
				"preflight server: bundle manifest omits required %s path %q",
				description,
				requiredPath,
			)
		}
	}
	if len(manifestEntries) != len(manifestDescriptions) {
		return ServerPreflightReport{}, fmt.Errorf(
			"preflight server: bundle manifest has %d entries, want exactly %d fixed entries",
			len(manifestEntries),
			len(manifestDescriptions),
		)
	}
	manifestHashes := make(map[string]string, len(manifestEntries))
	for _, entry := range manifestEntries {
		resolvedPath, resolveErr := dependencies.layout.resolveManifestPath(entry.path)
		if resolveErr != nil {
			return ServerPreflightReport{}, fmt.Errorf("preflight server: bundle manifest path %q: %w", entry.path, resolveErr)
		}
		manifestHashes[entry.path] = entry.sha256

		snapshot, alreadyTracked := tracked[resolvedPath]
		if !alreadyTracked {
			snapshot, resolveErr = snapshotServerAsset(
				resolvedPath,
				"OpenSSH bundle member "+entry.path,
				bundleMemberPolicy,
				dependencies.ownerValidator,
			)
			if resolveErr != nil {
				return ServerPreflightReport{}, resolveErr
			}
			tracked[resolvedPath] = snapshot
		}
		if snapshot.sha256 != entry.sha256 {
			return ServerPreflightReport{}, fmt.Errorf(
				"preflight server: bundle member %q SHA-256 is %s, want %s",
				entry.path,
				snapshot.sha256,
				entry.sha256,
			)
		}
	}
	sshdManifestPath := requiredManifestPaths["sshd"]
	if manifestHashes[sshdManifestPath] != config.SSHDBinarySHA256 {
		return ServerPreflightReport{}, fmt.Errorf(
			"preflight server: bundle manifest sshd SHA-256 is %s, want %s",
			manifestHashes[sshdManifestPath],
			config.SSHDBinarySHA256,
		)
	}

	openSSHReceipt, err := parseOpenSSHSourceReceipt(receiptSnapshot.data)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}
	openSSLReceipt, err := parseOpenSSLSourceReceipt(openSSLReceiptSnapshot.data)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}
	receiptEvidence, err := validateServerSourceReceipts(
		openSSHReceipt,
		openSSLReceipt,
		config.SSHDBinarySHA256,
		dependencies.platform,
		dependencies.architecture,
	)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}

	executableLinkage, err := inspectHeldServerExecutables(
		dependencies,
		selectedProfile,
		tracked,
	)
	if err != nil {
		return ServerPreflightReport{}, err
	}

	versionResult, err := runHeldServerCommand(
		ctx,
		dependencies,
		ancestors,
		environment,
		dependencies.layout.sshdPath,
		tracked[dependencies.layout.sshdPath],
		"-V",
	)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: query sshd version: %w", err)
	}
	engineVersion, err := validateServerVersionOutput(versionResult, selectedProfile)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}

	renderedConfig, err := server.Render(config)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: render expected sshd configuration: %w", err)
	}
	if !bytes.Equal(configSnapshot.data, renderedConfig) {
		return ServerPreflightReport{}, errors.New(
			"preflight server: installed sshd configuration does not byte-for-byte match rendered policy",
		)
	}

	if err := verifyHeldServerMetadata(
		dependencies.layout.hostKeyPath,
		"server host private key",
		hostKeyMetadata,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	keyResult, keyRunErr := runHeldServerCommand(
		ctx,
		dependencies,
		ancestors,
		environment,
		dependencies.layout.sshKeygenPath,
		tracked[dependencies.layout.sshKeygenPath],
		"-y",
		"-f",
		dependencies.layout.hostKeyPath,
	)
	if err := verifyHeldServerMetadata(
		dependencies.layout.hostKeyPath,
		"server host private key",
		hostKeyMetadata,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	if keyRunErr != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: derive host public key: %w", keyRunErr)
	}
	hostPublicKey, err := validateDerivedHostPublicKey(keyResult, selectedProfile)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}
	hostPublicKeyDigest := sha256.Sum256(hostPublicKey)

	authorizedKeysReport, err := server.ValidateAuthorizedKeys(config, authorizedKeysSnapshot.data)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: validate managed authorized_keys: %w", err)
	}

	if err := verifyHeldServerAssetIdentity(
		dependencies.layout.serverConfigPath,
		"rendered sshd configuration",
		configSnapshot,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	testResult, testRunErr := runHeldServerCommand(
		ctx,
		dependencies,
		ancestors,
		environment,
		dependencies.layout.sshdPath,
		tracked[dependencies.layout.sshdPath],
		"-t",
		"-f",
		dependencies.layout.serverConfigPath,
	)
	if err := verifyHeldServerAssetIdentity(
		dependencies.layout.serverConfigPath,
		"rendered sshd configuration",
		configSnapshot,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	if testRunErr != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: sshd configuration test: %w", testRunErr)
	}
	if len(testResult.stdout) != 0 || len(testResult.stderr) != 0 {
		return ServerPreflightReport{}, errors.New(
			"preflight server: sshd -t emitted unexpected output or diagnostics",
		)
	}

	if err := verifyHeldServerAssetIdentity(
		dependencies.layout.serverConfigPath,
		"rendered sshd configuration",
		configSnapshot,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	effectiveResult, effectiveRunErr := runHeldServerCommand(
		ctx,
		dependencies,
		ancestors,
		environment,
		dependencies.layout.sshdPath,
		tracked[dependencies.layout.sshdPath],
		"-T",
		"-f",
		dependencies.layout.serverConfigPath,
	)
	if err := verifyHeldServerAssetIdentity(
		dependencies.layout.serverConfigPath,
		"rendered sshd configuration",
		configSnapshot,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	if effectiveRunErr != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: resolve effective sshd configuration: %w", effectiveRunErr)
	}
	if len(effectiveResult.stderr) != 0 {
		return ServerPreflightReport{}, errors.New(
			"preflight server: sshd -T emitted diagnostics",
		)
	}
	if err := validateEffectiveServerConfig(effectiveResult.stdout, config, selectedProfile); err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: %w", err)
	}

	paths := make([]string, 0, len(tracked))
	for assetPath := range tracked {
		paths = append(paths, assetPath)
	}
	sort.Strings(paths)
	for _, assetPath := range paths {
		initial := tracked[assetPath]
		if err := verifyHeldServerAsset(
			assetPath,
			"critical server asset",
			initial,
			dependencies.ownerValidator,
		); err != nil {
			return ServerPreflightReport{}, err
		}
	}
	if err := revalidateHeldServerExecutables(
		dependencies,
		selectedProfile,
		tracked,
		executableLinkage,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	if err := verifyHeldServerMetadata(
		dependencies.layout.hostKeyPath,
		"server host private key",
		hostKeyMetadata,
		dependencies.ownerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	finalAccountEvidence, err := dependencies.accountInspector(config.DedicatedUser)
	if err != nil {
		return ServerPreflightReport{}, fmt.Errorf("preflight server: revalidate Unix account contract: %w", err)
	}
	if finalAccountEvidence != accountEvidence {
		return ServerPreflightReport{}, errors.New("preflight server: Unix account databases changed during preflight")
	}
	if err := ancestors.RequireDirectoryMode(
		dependencies.layout.privsepDirectory,
		0o755,
		dependencies.privsepOwnerValidator,
	); err != nil {
		return ServerPreflightReport{}, err
	}
	if err := ancestors.Verify(dependencies.ownerValidator); err != nil {
		return ServerPreflightReport{}, err
	}

	return ServerPreflightReport{
		SSHDPath:                    installlayout.SSHDPath,
		SSHDBinarySHA256:            config.SSHDBinarySHA256,
		OpenSSHBundleManifestSHA256: config.OpenSSHBundleManifestSHA256,
		EngineVersion:               engineVersion,
		Profile:                     selectedProfile.ID,
		OpenSSLVersion:              openSSLReceipt["version"],
		OpenSSLVersionText:          selectedProfile.OpenSSLVersionText,
		OpenSSLLinkage:              executableLinkage[0].report.openSSLLinkage,
		ExecutableFormat:            executableLinkage[0].report.format,
		StaticLibcryptoSHA256:       receiptEvidence.staticLibcryptoSHA256,
		HostPublicKeySHA256:         hex.EncodeToString(hostPublicKeyDigest[:]),
		AuthorizedKeyCount:          authorizedKeysReport.KeyCount,
	}, nil
}

func productionServerArchitecture(goArchitecture string) string {
	switch goArchitecture {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return goArchitecture
	}
}

func validateServerBuildPlatform(platform, architecture string) error {
	if platform != "linux" {
		return fmt.Errorf("installed OpenSSH bundle platform is %q, want linux", platform)
	}
	if architecture != "x86_64" && architecture != "aarch64" {
		return fmt.Errorf(
			"installed OpenSSH bundle architecture is %q, want x86_64 or aarch64",
			architecture,
		)
	}
	return nil
}

func inspectHeldServerExecutables(
	dependencies serverPreflightDependencies,
	selected profile.Profile,
	tracked map[string]serverAssetSnapshot,
) ([]serverExecutableLinkageEvidence, error) {
	paths := []string{
		dependencies.layout.sshPath,
		dependencies.layout.sshKeygenPath,
		dependencies.layout.sshdPath,
		dependencies.layout.sshdAuthPath,
		dependencies.layout.sshdSessionPath,
	}
	evidence := make([]serverExecutableLinkageEvidence, 0, len(paths))
	for _, executablePath := range paths {
		snapshot, exists := tracked[executablePath]
		if !exists || snapshot.file == nil {
			return nil, fmt.Errorf(
				"preflight server: retained executable %q has no held descriptor",
				executablePath,
			)
		}
		if err := verifyHeldServerAssetIdentity(
			executablePath,
			"retained OpenSSH executable",
			snapshot,
			dependencies.ownerValidator,
		); err != nil {
			return nil, err
		}
		linkage, err := dependencies.inspector.Inspect(snapshot.file)
		if err != nil {
			return nil, fmt.Errorf(
				"preflight server: inspect retained OpenSSH executable %q: %w",
				executablePath,
				err,
			)
		}
		if linkage.format != selected.ExecutableFormat {
			return nil, fmt.Errorf(
				"preflight server: retained OpenSSH executable %q format is %q, want %q",
				executablePath,
				linkage.format,
				selected.ExecutableFormat,
			)
		}
		if linkage.openSSLLinkage != selected.OpenSSLLinkage {
			return nil, fmt.Errorf(
				"preflight server: retained OpenSSH executable %q OpenSSL linkage is %q, want %q",
				executablePath,
				linkage.openSSLLinkage,
				selected.OpenSSLLinkage,
			)
		}
		if err := verifyHeldServerAssetIdentity(
			executablePath,
			"retained OpenSSH executable",
			snapshot,
			dependencies.ownerValidator,
		); err != nil {
			return nil, err
		}
		evidence = append(evidence, serverExecutableLinkageEvidence{
			path:   executablePath,
			report: linkage,
		})
	}
	return evidence, nil
}

func revalidateHeldServerExecutables(
	dependencies serverPreflightDependencies,
	selected profile.Profile,
	tracked map[string]serverAssetSnapshot,
	initial []serverExecutableLinkageEvidence,
) error {
	final, err := inspectHeldServerExecutables(dependencies, selected, tracked)
	if err != nil {
		return err
	}
	if len(final) != len(initial) {
		return errors.New("preflight server: retained OpenSSH executable inventory changed")
	}
	for index := range initial {
		if initial[index].path != final[index].path ||
			!initial[index].report.equal(final[index].report) {
			return fmt.Errorf(
				"preflight server: retained OpenSSH executable %q linkage evidence changed",
				initial[index].path,
			)
		}
	}
	return nil
}

func validateServerPreflightLayout(layout serverPreflightLayout) error {
	if !filepath.IsAbs(layout.stageRoot) || filepath.Clean(layout.stageRoot) != layout.stageRoot {
		return errors.New("preflight server: injected stage root must be a clean absolute path")
	}
	paths := []string{
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
		layout.privsepDirectory,
	}
	for _, candidate := range paths {
		if !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
			return fmt.Errorf("preflight server: injected layout path %q must be clean and absolute", candidate)
		}
		if !pathWithinRoot(layout.stageRoot, candidate) {
			return fmt.Errorf("preflight server: injected layout path %q escapes stage root", candidate)
		}
	}
	return nil
}

func (layout serverPreflightLayout) resolveManifestPath(manifestPath string) (string, error) {
	prefix := strings.TrimPrefix(filepath.ToSlash(installlayout.OpenSSHPrefix), "/") + "/"
	if !strings.HasPrefix(manifestPath, prefix) && !isFixedServerManifestMetadataPath(manifestPath) {
		return "", errors.New("path is outside the fixed server stage tree")
	}
	resolved := filepath.Join(layout.stageRoot, filepath.FromSlash(manifestPath))
	if !pathWithinRoot(layout.stageRoot, resolved) {
		return "", errors.New("resolved path escapes the fixed stage root")
	}
	return resolved, nil
}

func requiredServerManifestPaths(layout serverPreflightLayout) (map[string]string, error) {
	logical := map[string]string{
		"ssh":                    layout.sshPath,
		"sshd":                   layout.sshdPath,
		"sshd-auth":              layout.sshdAuthPath,
		"sshd-session":           layout.sshdSessionPath,
		"ssh-keygen":             layout.sshKeygenPath,
		"OpenSSH source receipt": layout.sourceReceiptPath,
		"OpenSSL source receipt": layout.openSSLReceiptPath,
		"OpenSSH license":        layout.openSSHLicensePath,
		"OpenSSL license":        layout.openSSLLicensePath,
	}
	result := make(map[string]string, len(logical))
	for description, physical := range logical {
		relative, err := filepath.Rel(layout.stageRoot, physical)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
			return nil, fmt.Errorf("preflight server: required %s path is outside stage root", description)
		}
		result[description] = filepath.ToSlash(relative)
	}
	return result, nil
}

func physicalPathForLogical(stageRoot, logical string) string {
	return filepath.Join(stageRoot, strings.TrimPrefix(filepath.Clean(logical), string(filepath.Separator)))
}

func pathWithinRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func snapshotServerAsset(
	assetPath,
	description string,
	policy serverAssetPolicy,
	ownerValidator serverOwnerValidator,
) (serverAssetSnapshot, error) {
	if policy.maximumBytes <= 0 {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: %s has an invalid byte limit", description)
	}
	pathInfo, err := os.Lstat(assetPath)
	if err != nil {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: inspect %s %q: %w", description, assetPath, err)
	}
	if err := validateServerAssetInfo(assetPath, description, pathInfo, policy, ownerValidator); err != nil {
		return serverAssetSnapshot{}, err
	}
	if pathInfo.Size() > policy.maximumBytes {
		return serverAssetSnapshot{}, fmt.Errorf(
			"preflight server: %s %q exceeds %d bytes",
			description,
			assetPath,
			policy.maximumBytes,
		)
	}

	file, err := os.Open(assetPath)
	if err != nil {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: open %s %q: %w", description, assetPath, err)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = file.Close()
		}
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: inspect opened %s %q: %w", description, assetPath, err)
	}
	if err := validateServerAssetInfo(assetPath, description, openedInfo, policy, ownerValidator); err != nil {
		return serverAssetSnapshot{}, err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: %s %q was replaced while opening", description, assetPath)
	}
	if pathInfo.Size() != openedInfo.Size() || pathInfo.Mode() != openedInfo.Mode() ||
		!pathInfo.ModTime().Equal(openedInfo.ModTime()) {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: %s %q changed while opening", description, assetPath)
	}

	contents, err := io.ReadAll(io.LimitReader(file, policy.maximumBytes+1))
	if err != nil {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: read %s %q: %w", description, assetPath, err)
	}
	if int64(len(contents)) > policy.maximumBytes {
		return serverAssetSnapshot{}, fmt.Errorf(
			"preflight server: %s %q exceeds %d bytes",
			description,
			assetPath,
			policy.maximumBytes,
		)
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: re-inspect %s %q: %w", description, assetPath, err)
	}
	if !os.SameFile(openedInfo, afterInfo) || openedInfo.Size() != afterInfo.Size() ||
		!openedInfo.ModTime().Equal(afterInfo.ModTime()) {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: %s %q changed while reading", description, assetPath)
	}
	if int64(len(contents)) != afterInfo.Size() {
		return serverAssetSnapshot{}, fmt.Errorf("preflight server: %s %q changed size while reading", description, assetPath)
	}
	digest := sha256.Sum256(contents)
	keepOpen = true
	return serverAssetSnapshot{
		data:   contents,
		sha256: hex.EncodeToString(digest[:]),
		info:   afterInfo,
		policy: policy,
		file:   file,
	}, nil
}

func snapshotServerAssetMetadata(
	assetPath,
	description string,
	policy serverAssetPolicy,
	ownerValidator serverOwnerValidator,
) (serverAssetMetadataSnapshot, error) {
	if policy.maximumBytes <= 0 {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: %s has an invalid byte limit",
			description,
		)
	}
	pathInfo, err := os.Lstat(assetPath)
	if err != nil {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: inspect %s %q: %w",
			description,
			assetPath,
			err,
		)
	}
	if err := validateServerAssetInfo(assetPath, description, pathInfo, policy, ownerValidator); err != nil {
		return serverAssetMetadataSnapshot{}, err
	}
	if pathInfo.Size() > policy.maximumBytes {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: %s %q exceeds %d bytes",
			description,
			assetPath,
			policy.maximumBytes,
		)
	}

	// Opening the fixed path and comparing its identity closes the lstat/open
	// substitution window without ever reading private-key contents.
	file, err := os.Open(assetPath)
	if err != nil {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: open %s %q: %w",
			description,
			assetPath,
			err,
		)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = file.Close()
		}
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: inspect opened %s %q: %w",
			description,
			assetPath,
			err,
		)
	}
	if err := validateServerAssetInfo(assetPath, description, openedInfo, policy, ownerValidator); err != nil {
		return serverAssetMetadataSnapshot{}, err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: %s %q was replaced while opening",
			description,
			assetPath,
		)
	}
	if pathInfo.Size() != openedInfo.Size() || pathInfo.Mode() != openedInfo.Mode() ||
		!pathInfo.ModTime().Equal(openedInfo.ModTime()) {
		return serverAssetMetadataSnapshot{}, fmt.Errorf(
			"preflight server: %s %q changed while opening",
			description,
			assetPath,
		)
	}
	keepOpen = true
	return serverAssetMetadataSnapshot{
		info:   openedInfo,
		policy: policy,
		file:   file,
	}, nil
}

func closeServerPreflightSnapshots(
	tracked map[string]serverAssetSnapshot,
	hostKey *serverAssetMetadataSnapshot,
) {
	for _, snapshot := range tracked {
		if snapshot.file != nil {
			_ = snapshot.file.Close()
		}
	}
	if hostKey != nil && hostKey.file != nil {
		_ = hostKey.file.Close()
	}
}

func verifyHeldServerAssetIdentity(
	assetPath,
	description string,
	initial serverAssetSnapshot,
	ownerValidator serverOwnerValidator,
) error {
	if initial.file == nil {
		return fmt.Errorf("preflight server: %s %q has no held descriptor", description, assetPath)
	}
	pathInfo, err := os.Lstat(assetPath)
	if err != nil {
		return fmt.Errorf("preflight server: re-inspect %s %q: %w", description, assetPath, err)
	}
	if err := validateServerAssetInfo(assetPath, description, pathInfo, initial.policy, ownerValidator); err != nil {
		return err
	}
	heldInfo, err := initial.file.Stat()
	if err != nil {
		return fmt.Errorf("preflight server: inspect held %s %q: %w", description, assetPath, err)
	}
	if err := validateServerAssetInfo(assetPath, description, heldInfo, initial.policy, ownerValidator); err != nil {
		return err
	}
	if !os.SameFile(initial.info, heldInfo) || !os.SameFile(initial.info, pathInfo) {
		return fmt.Errorf("preflight server: %s %q was substituted", description, assetPath)
	}
	if initial.info.Size() != heldInfo.Size() || initial.info.Size() != pathInfo.Size() ||
		initial.info.Mode() != heldInfo.Mode() || initial.info.Mode() != pathInfo.Mode() ||
		!initial.info.ModTime().Equal(heldInfo.ModTime()) ||
		!initial.info.ModTime().Equal(pathInfo.ModTime()) {
		return fmt.Errorf("preflight server: %s %q changed during preflight", description, assetPath)
	}
	return nil
}

func verifyHeldServerAsset(
	assetPath,
	description string,
	initial serverAssetSnapshot,
	ownerValidator serverOwnerValidator,
) error {
	if err := verifyHeldServerAssetIdentity(assetPath, description, initial, ownerValidator); err != nil {
		return err
	}
	if _, err := initial.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("preflight server: rewind held %s %q: %w", description, assetPath, err)
	}
	contents, err := io.ReadAll(io.LimitReader(initial.file, initial.policy.maximumBytes+1))
	if err != nil {
		return fmt.Errorf("preflight server: re-read held %s %q: %w", description, assetPath, err)
	}
	if int64(len(contents)) > initial.policy.maximumBytes {
		return fmt.Errorf(
			"preflight server: %s %q exceeds %d bytes",
			description,
			assetPath,
			initial.policy.maximumBytes,
		)
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != initial.sha256 {
		return fmt.Errorf("preflight server: %s %q changed during preflight", description, assetPath)
	}
	return verifyHeldServerAssetIdentity(assetPath, description, initial, ownerValidator)
}

func verifyHeldServerMetadata(
	assetPath,
	description string,
	initial serverAssetMetadataSnapshot,
	ownerValidator serverOwnerValidator,
) error {
	if initial.file == nil {
		return fmt.Errorf("preflight server: %s %q has no held descriptor", description, assetPath)
	}
	pathInfo, err := os.Lstat(assetPath)
	if err != nil {
		return fmt.Errorf("preflight server: re-inspect %s %q: %w", description, assetPath, err)
	}
	if err := validateServerAssetInfo(assetPath, description, pathInfo, initial.policy, ownerValidator); err != nil {
		return err
	}
	heldInfo, err := initial.file.Stat()
	if err != nil {
		return fmt.Errorf("preflight server: inspect held %s %q: %w", description, assetPath, err)
	}
	if err := validateServerAssetInfo(assetPath, description, heldInfo, initial.policy, ownerValidator); err != nil {
		return err
	}
	if !os.SameFile(initial.info, heldInfo) || !os.SameFile(initial.info, pathInfo) {
		return fmt.Errorf("preflight server: %s %q was substituted", description, assetPath)
	}
	if initial.info.Size() != heldInfo.Size() || initial.info.Size() != pathInfo.Size() ||
		initial.info.Mode() != heldInfo.Mode() || initial.info.Mode() != pathInfo.Mode() ||
		!initial.info.ModTime().Equal(heldInfo.ModTime()) ||
		!initial.info.ModTime().Equal(pathInfo.ModTime()) {
		return fmt.Errorf("preflight server: %s %q changed during preflight", description, assetPath)
	}
	return nil
}

func runHeldServerCommand(
	ctx context.Context,
	dependencies serverPreflightDependencies,
	ancestors *serverAncestorSet,
	environment []string,
	commandPath string,
	commandSnapshot serverAssetSnapshot,
	arguments ...string,
) (serverCommandResult, error) {
	if err := ancestors.Verify(dependencies.ownerValidator); err != nil {
		return serverCommandResult{}, err
	}
	if err := verifyHeldServerAssetIdentity(
		commandPath,
		"server command executable",
		commandSnapshot,
		dependencies.ownerValidator,
	); err != nil {
		return serverCommandResult{}, err
	}
	result, runErr := dependencies.runner.Run(ctx, commandPath, environment, arguments...)
	if err := verifyHeldServerAssetIdentity(
		commandPath,
		"server command executable",
		commandSnapshot,
		dependencies.ownerValidator,
	); err != nil {
		return result, err
	}
	if err := ancestors.Verify(dependencies.ownerValidator); err != nil {
		return result, err
	}
	return result, runErr
}

func validateServerAssetInfo(
	assetPath,
	description string,
	info os.FileInfo,
	policy serverAssetPolicy,
	ownerValidator serverOwnerValidator,
) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("preflight server: %s %q must not be a symbolic link", description, assetPath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("preflight server: %s %q must be a regular file", description, assetPath)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("preflight server: %s %q has unsafe special mode bits", description, assetPath)
	}
	permissions := info.Mode().Perm()
	if permissions&policy.forbidden != 0 {
		return fmt.Errorf(
			"preflight server: %s %q permissions %04o are too broad",
			description,
			assetPath,
			permissions,
		)
	}
	switch policy.execution {
	case executionRequired:
		if permissions&0o111 == 0 {
			return fmt.Errorf("preflight server: %s %q is not executable", description, assetPath)
		}
	case executionForbidden:
		if permissions&0o111 != 0 {
			return fmt.Errorf("preflight server: %s %q must not be executable", description, assetPath)
		}
	}
	if err := ownerValidator(assetPath, info); err != nil {
		return fmt.Errorf("preflight server: %s %q: %w", description, assetPath, err)
	}
	return nil
}

func parseBundleManifest(contents []byte) ([]bundleManifestEntry, error) {
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return nil, errors.New("OpenSSH bundle manifest must be non-empty and LF-terminated")
	}
	lines := strings.Split(string(contents[:len(contents)-1]), "\n")
	entries := make([]bundleManifestEntry, 0, len(lines))
	previousPath := ""
	for index, line := range lines {
		if len(line) < sha256.Size*2+3 || line[sha256.Size*2:sha256.Size*2+2] != "  " {
			return nil, fmt.Errorf("OpenSSH bundle manifest line %d has invalid sha256sum syntax", index+1)
		}
		digest := line[:sha256.Size*2]
		if !isLowerHexSHA256(digest) {
			return nil, fmt.Errorf("OpenSSH bundle manifest line %d has a non-lowercase SHA-256", index+1)
		}
		manifestPath := line[sha256.Size*2+2:]
		if err := validateBundleManifestPath(manifestPath); err != nil {
			return nil, fmt.Errorf("OpenSSH bundle manifest line %d: %w", index+1, err)
		}
		if previousPath != "" && manifestPath <= previousPath {
			return nil, fmt.Errorf("OpenSSH bundle manifest paths are not strictly sorted and unique at %q", manifestPath)
		}
		previousPath = manifestPath
		entries = append(entries, bundleManifestEntry{path: manifestPath, sha256: digest})
	}
	return entries, nil
}

func validateBundleManifestPath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return fmt.Errorf("bundle path %q must be a relative POSIX path", value)
	}
	if path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("bundle path %q is not canonical", value)
	}
	for _, character := range []byte(value) {
		if character == '/' || character == '.' || character == '_' || character == '-' || character == '+' ||
			character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' {
			continue
		}
		return fmt.Errorf("bundle path %q contains an unsafe character", value)
	}
	prefix := strings.TrimPrefix(filepath.ToSlash(installlayout.OpenSSHPrefix), "/") + "/"
	if !strings.HasPrefix(value, prefix) && !isFixedServerManifestMetadataPath(value) {
		return fmt.Errorf("bundle path %q is outside the fixed server stage tree", value)
	}
	return nil
}

func isFixedServerManifestMetadataPath(value string) bool {
	for _, fixedPath := range []string{
		installlayout.OpenSSHSourceReceiptPath,
		installlayout.OpenSSLSourceReceiptPath,
		installlayout.OpenSSHLicensePath,
		installlayout.OpenSSLLicensePath,
	} {
		if value == strings.TrimPrefix(filepath.ToSlash(fixedPath), "/") {
			return true
		}
	}
	return false
}

var openSSHSourceReceiptOrder = [...]string{
	"receipt_version",
	"version",
	"engine_version",
	"source_url",
	"source_sha256",
	"release_key_fingerprint",
	"configure_prefix",
	"sysconfdir",
	"privsep_user",
	"privsep_path",
	"hardening",
	"pie",
	"kerberos5",
	"ldns",
	"libedit",
	"pam",
	"selinux",
	"zlib",
	"sshd_path",
	"sshd_sha256",
	"target_tuple",
	"openssl_prefix",
	"openssl_source_receipt_path",
	"openssl_source_sha256",
	"openssl_linkage",
	"elf_dynamic_policy",
	"tests",
}

var openSSLSourceReceiptOrder = [...]string{
	"receipt_version",
	"version",
	"source_url",
	"source_sha256",
	"release_key_fingerprint",
	"platform",
	"architecture",
	"configure_prefix",
	"openssl_config_directory",
	"shared",
	"module",
	"dso",
	"pinshared",
	"tests",
	"linkage",
	"static_libcrypto_sha256",
	"license_path",
}

func parseOpenSSHSourceReceipt(contents []byte) (map[string]string, error) {
	return parseOrderedSourceReceipt("OpenSSH", contents, openSSHSourceReceiptOrder[:])
}

func parseOpenSSLSourceReceipt(contents []byte) (map[string]string, error) {
	return parseOrderedSourceReceipt("OpenSSL", contents, openSSLSourceReceiptOrder[:])
}

func parseOrderedSourceReceipt(
	name string,
	contents []byte,
	order []string,
) (map[string]string, error) {
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return nil, fmt.Errorf("%s source receipt must be non-empty and LF-terminated", name)
	}
	for _, value := range contents {
		if value == '\n' || value >= 0x20 && value <= 0x7e {
			continue
		}
		return nil, fmt.Errorf("%s source receipt contains a non-ASCII or control byte", name)
	}
	lines := strings.Split(string(contents[:len(contents)-1]), "\n")
	if len(lines) != len(order) {
		return nil, fmt.Errorf("%s source receipt has %d fields, want %d", name, len(lines), len(order))
	}
	values := make(map[string]string, len(order))
	for index, expectedKey := range order {
		key, value, found := strings.Cut(lines[index], "=")
		if !found || key != expectedKey {
			return nil, fmt.Errorf(
				"%s source receipt field %d is %q, want %q",
				name,
				index+1,
				key,
				expectedKey,
			)
		}
		values[key] = value
	}
	return values, nil
}

func validateServerSourceReceipts(
	openSSHValues,
	openSSLValues map[string]string,
	sshdSHA256,
	platform,
	architecture string,
) (serverSourceReceiptEvidence, error) {
	if err := validateServerBuildPlatform(platform, architecture); err != nil {
		return serverSourceReceiptEvidence{}, err
	}
	openSSHExpected := map[string]string{
		"receipt_version":             "1",
		"version":                     opensshsource.Version,
		"engine_version":              opensshsource.EngineVersion,
		"source_url":                  opensshsource.SourceURL,
		"source_sha256":               opensshsource.SourceSHA256,
		"release_key_fingerprint":     opensshsource.ReleaseKeyFingerprint,
		"configure_prefix":            installlayout.OpenSSHPrefix,
		"sysconfdir":                  expectedOpenSSHSysconfDir,
		"privsep_user":                installlayout.PrivsepUser,
		"privsep_path":                installlayout.PrivsepDirectory,
		"hardening":                   "yes",
		"pie":                         "yes",
		"kerberos5":                   "no",
		"ldns":                        "no",
		"libedit":                     "no",
		"pam":                         "no",
		"selinux":                     "no",
		"zlib":                        "no",
		"sshd_path":                   installlayout.SSHDPath,
		"sshd_sha256":                 sshdSHA256,
		"openssl_prefix":              opensslsource.LogicalPrefix,
		"openssl_source_receipt_path": installlayout.OpenSSLSourceReceiptPath,
		"openssl_source_sha256":       opensslsource.SourceSHA256,
		"openssl_linkage":             staticOpenSSLLinkage,
		"elf_dynamic_policy":          "passed",
		"tests":                       "passed",
	}
	if err := validateOrderedReceiptValues(
		"OpenSSH",
		openSSHValues,
		openSSHSourceReceiptOrder[:],
		openSSHExpected,
	); err != nil {
		return serverSourceReceiptEvidence{}, err
	}
	if err := validateOpenSSHTargetTuple(openSSHValues["target_tuple"], architecture); err != nil {
		return serverSourceReceiptEvidence{}, err
	}

	openSSLExpected := map[string]string{
		"receipt_version":          "1",
		"version":                  opensslsource.Version,
		"source_url":               opensslsource.SourceURL,
		"source_sha256":            opensslsource.SourceSHA256,
		"release_key_fingerprint":  opensslsource.ReleaseKeyFingerprint,
		"platform":                 "linux",
		"architecture":             architecture,
		"configure_prefix":         opensslsource.LogicalPrefix,
		"openssl_config_directory": opensslsource.LogicalConfigDirectory,
		"shared":                   "no",
		"module":                   "no",
		"dso":                      "no",
		"pinshared":                "no",
		"tests":                    "passed",
		"linkage":                  staticOpenSSLLinkage,
		"license_path":             installlayout.OpenSSLLicensePath,
	}
	if err := validateOrderedReceiptValues(
		"OpenSSL",
		openSSLValues,
		openSSLSourceReceiptOrder[:],
		openSSLExpected,
	); err != nil {
		return serverSourceReceiptEvidence{}, err
	}
	staticLibcryptoSHA256 := openSSLValues["static_libcrypto_sha256"]
	if !isLowerHexSHA256(staticLibcryptoSHA256) {
		return serverSourceReceiptEvidence{}, errors.New(
			"OpenSSL source receipt static_libcrypto_sha256 must contain exactly 64 lowercase hexadecimal characters",
		)
	}

	crossReceiptValues := []struct {
		openSSHKey string
		openSSLKey string
	}{
		{openSSHKey: "openssl_prefix", openSSLKey: "configure_prefix"},
		{openSSHKey: "openssl_source_sha256", openSSLKey: "source_sha256"},
		{openSSHKey: "openssl_linkage", openSSLKey: "linkage"},
	}
	for _, binding := range crossReceiptValues {
		if openSSHValues[binding.openSSHKey] != openSSLValues[binding.openSSLKey] {
			return serverSourceReceiptEvidence{}, fmt.Errorf(
				"OpenSSH source receipt %s does not match OpenSSL source receipt %s",
				binding.openSSHKey,
				binding.openSSLKey,
			)
		}
	}
	return serverSourceReceiptEvidence{
		staticLibcryptoSHA256: staticLibcryptoSHA256,
	}, nil
}

func validateOrderedReceiptValues(
	name string,
	values map[string]string,
	order []string,
	expected map[string]string,
) error {
	for _, key := range order {
		want, exists := expected[key]
		if !exists {
			continue
		}
		if got := values[key]; got != want {
			return fmt.Errorf("%s source receipt %s is %q, want %q", name, key, got, want)
		}
	}
	return nil
}

func validateOpenSSHTargetTuple(targetTuple, architecture string) error {
	if targetTuple == "" {
		return errors.New("OpenSSH source receipt target_tuple must be non-empty")
	}
	for _, character := range []byte(targetTuple) {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return fmt.Errorf("OpenSSH source receipt target_tuple %q contains an unsafe character", targetTuple)
	}
	if !strings.HasPrefix(targetTuple, architecture+"-") {
		return fmt.Errorf(
			"OpenSSH source receipt target_tuple %q does not match architecture %q",
			targetTuple,
			architecture,
		)
	}
	return nil
}

func validateServerVersionOutput(
	result serverCommandResult,
	selected profile.Profile,
) (string, error) {
	if len(result.stdout) != 0 {
		return "", fmt.Errorf("sshd -V wrote unexpected stdout %q", result.stdout)
	}
	expected := []byte(selected.EngineVersion + ", " + selected.OpenSSLVersionText + "\n")
	if !bytes.Equal(result.stderr, expected) {
		return "", fmt.Errorf(
			"sshd -V stderr is %q, want exact profile output %q",
			result.stderr,
			expected,
		)
	}
	return selected.EngineVersion, nil
}

func validateDerivedHostPublicKey(result serverCommandResult, selected profile.Profile) ([]byte, error) {
	if len(result.stderr) != 0 {
		return nil, errors.New("ssh-keygen -y emitted diagnostics")
	}
	if len(result.stdout) == 0 || result.stdout[len(result.stdout)-1] != '\n' ||
		bytes.Count(result.stdout, []byte{'\n'}) != 1 || bytes.Contains(result.stdout, []byte{'\r'}) {
		return nil, errors.New("ssh-keygen -y did not emit exactly one LF-terminated public key")
	}
	line := result.stdout[:len(result.stdout)-1]
	algorithm, remainder, found := bytes.Cut(line, []byte{' '})
	if !found || len(algorithm) == 0 || len(remainder) == 0 {
		return nil, errors.New("ssh-keygen -y public key is not canonical")
	}
	encoded := remainder
	if separator := bytes.IndexByte(remainder, ' '); separator >= 0 {
		encoded = remainder[:separator]
		comment := remainder[separator+1:]
		if len(encoded) == 0 || len(comment) == 0 || !utf8.Valid(comment) {
			return nil, errors.New("ssh-keygen -y public-key comment is not canonical")
		}
		for _, character := range string(comment) {
			if unicode.IsControl(character) {
				return nil, errors.New("ssh-keygen -y public-key comment contains a control character")
			}
		}
	}
	if string(algorithm) != selected.AuthenticationKeyType {
		return nil, fmt.Errorf(
			"host public-key type %q does not match %q",
			algorithm,
			selected.AuthenticationKeyType,
		)
	}
	if err := sshwire.ValidatePublicKeyBlob(
		string(encoded),
		selected.AuthenticationKeyType,
		selected.RawPublicKeyBytes,
	); err != nil {
		return nil, fmt.Errorf("validate host public-key blob: %w", err)
	}
	// OpenSSH 10.4p1 preserves the private key's comment in composite
	// ssh-keygen -y output. Comments are non-cryptographic metadata, so report
	// identity over a deterministic comment-free public-key representation.
	canonical := make([]byte, 0, len(algorithm)+1+len(encoded)+1)
	canonical = append(canonical, algorithm...)
	canonical = append(canonical, ' ')
	canonical = append(canonical, encoded...)
	canonical = append(canonical, '\n')
	return canonical, nil
}

func validateEffectiveServerConfig(output []byte, config server.Config, selected profile.Profile) error {
	options, err := parseEffectiveServerOptions(output)
	if err != nil {
		return err
	}
	listenAddress := config.Listen.Address.Unmap()
	addressFamily := "inet6"
	if listenAddress.Is4() {
		addressFamily = "inet"
	}
	listen := net.JoinHostPort(listenAddress.String(), strconv.Itoa(int(config.Listen.Port)))
	target := netip.AddrPortFrom(config.Target.Address.Unmap(), uint16(config.Target.Port)).String()
	expected := map[string][]string{
		"addressfamily":                {addressFamily},
		"port":                         {strconv.Itoa(int(config.Listen.Port))},
		"listenaddress":                {listen},
		"pidfile":                      {expectedServerPIDFile},
		"hostkey":                      {config.HostKeyPath},
		"hostkeyalgorithms":            {selected.AuthenticationKeyType},
		"kexalgorithms":                {selected.KeyExchangeAlgorithm},
		"pubkeyacceptedalgorithms":     {selected.AuthenticationKeyType},
		"ciphers":                      {strings.Join(selected.Ciphers, ",")},
		"rekeylimit":                   {"536870912 3600"},
		"compression":                  {"no"},
		"authenticationmethods":        {"publickey"},
		"pubkeyauthentication":         {"yes"},
		"passwordauthentication":       {"no"},
		"kbdinteractiveauthentication": {"no"},
		"hostbasedauthentication":      {"no"},
		"permitemptypasswords":         {"no"},
		"permitrootlogin":              {"no"},
		"strictmodes":                  {"yes"},
		"allowusers":                   {config.DedicatedUser},
		"authorizedkeysfile":           {config.AuthorizedKeysPath},
		"maxauthtries":                 {"3"},
		"logingracetime":               {"30"},
		"maxstartups":                  {"10:30:60"},
		"maxsessions":                  {"0"},
		"allowtcpforwarding":           {"local"},
		"permitopen":                   {target},
		"permitlisten":                 {"none"},
		"allowstreamlocalforwarding":   {"no"},
		"allowagentforwarding":         {"no"},
		"x11forwarding":                {"no"},
		"permittty":                    {"no"},
		"permittunnel":                 {"no"},
		"gatewayports":                 {"no"},
		"permituserrc":                 {"no"},
		"permituserenvironment":        {"no"},
		"exposeauthinfo":               {"no"},
		"printlastlog":                 {"no"},
		"printmotd":                    {"no"},
		"usedns":                       {"no"},
		"tcpkeepalive":                 {"no"},
		"clientaliveinterval":          {"30"},
		"clientalivecountmax":          {"3"},
		"versionaddendum":              {"none"},
		"loglevel":                     {"VERBOSE"},
		"disableforwarding":            {"no"},
		"forcecommand":                 {"none"},
		"chrootdirectory":              {"none"},
		"authorizedkeyscommand":        {"none"},
		"authorizedprincipalscommand":  {"none"},
		"authorizedprincipalsfile":     {"none"},
		"trustedusercakeys":            {"none"},
		"hostkeyagent":                 {"none"},
	}
	for key, want := range expected {
		got := options[key]
		if len(got) != len(want) {
			return fmt.Errorf("effective sshd option %s has %d values, want %d", key, len(got), len(want))
		}
		for index := range want {
			if got[index] != want[index] {
				return fmt.Errorf("effective sshd option %s is %q, want %q", key, got[index], want[index])
			}
		}
	}
	for _, optionalDisabled := range []string{"gssapiauthentication", "kerberosauthentication", "usepam"} {
		if values, present := options[optionalDisabled]; present &&
			(len(values) != 1 || values[0] != "no") {
			return fmt.Errorf("effective sshd option %s is %q, want no or compiled-out", optionalDisabled, values)
		}
	}
	for _, forbidden := range []string{
		"acceptenv",
		"allowgroups",
		"denygroups",
		"denyusers",
		"subsystem",
	} {
		if values, present := options[forbidden]; present {
			return fmt.Errorf("effective sshd option %s must be absent, got %q", forbidden, values)
		}
	}
	return nil
}

func parseEffectiveServerOptions(output []byte) (map[string][]string, error) {
	if len(output) == 0 || output[len(output)-1] != '\n' || !utf8.Valid(output) {
		return nil, errors.New("sshd -T output must be non-empty, valid UTF-8, and LF-terminated")
	}
	options := make(map[string][]string)
	lines := strings.Split(string(output[:len(output)-1]), "\n")
	for index, line := range lines {
		if line == "" || strings.ContainsAny(line, "\r\x00") {
			return nil, fmt.Errorf("sshd -T output line %d is malformed", index+1)
		}
		key, value, found := strings.Cut(line, " ")
		if !found || value == "" || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("sshd -T output line %d is malformed", index+1)
		}
		for _, character := range []byte(key) {
			if !(character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9') {
				return nil, fmt.Errorf("sshd -T option name %q is unsafe", key)
			}
		}
		// OpenSSH 10.4p1 emits a mixture of lower-case and source-spelling
		// option names, including AddressFamily and LoginGraceTime. sshd_config
		// names are ASCII case-insensitive, so normalize only after enforcing a
		// narrow alphanumeric grammar.
		key = strings.ToLower(key)
		options[key] = append(options[key], value)
	}
	return options, nil
}

func isLowerHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range []byte(value) {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

type execServerCommandRunner struct{}

func (execServerCommandRunner) Run(
	ctx context.Context,
	commandPath string,
	environment []string,
	arguments ...string,
) (serverCommandResult, error) {
	stdout := boundedServerCommandBuffer{maximum: maxServerCommandOutput}
	stderr := boundedServerCommandBuffer{maximum: maxServerCommandOutput}
	command := exec.CommandContext(ctx, commandPath, arguments...)
	command.Env = append([]string(nil), environment...)
	command.Stdin = nil
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := serverCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if stdout.overflow || stderr.overflow {
		return result, fmt.Errorf("command output exceeds %d bytes", maxServerCommandOutput)
	}
	return result, err
}

type boundedServerCommandBuffer struct {
	contents bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *boundedServerCommandBuffer) Write(input []byte) (int, error) {
	remaining := buffer.maximum - buffer.contents.Len()
	if remaining > 0 {
		write := len(input)
		if write > remaining {
			write = remaining
		}
		_, _ = buffer.contents.Write(input[:write])
	}
	if len(input) > remaining {
		buffer.overflow = true
	}
	return len(input), nil
}

func (buffer *boundedServerCommandBuffer) Bytes() []byte {
	return append([]byte(nil), buffer.contents.Bytes()...)
}
