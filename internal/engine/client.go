// Package engine confines all interaction with the bundled OpenSSH data plane.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/profile"
)

const (
	hostAlias         = "warptweet-peer"
	controlSocketName = "c"
)

// Binary identifies the exact OpenSSH executable that may enter the data path.
type Binary struct {
	Path   string
	SHA256 string
}

// ClientSpec contains the already-validated values used to derive the closed
// OpenSSH client policy. Path fields are internal controller state, never .wt
// manifest authority.
type ClientSpec struct {
	TunnelID             string
	ServerAddress        netip.Addr
	ServerPort           uint16
	ServerUser           string
	ListenAddress        netip.Addr
	ListenPort           uint16
	TargetAddress        netip.Addr
	TargetPort           uint16
	IdentityFile         string
	KnownHostsFile       string
	GlobalKnownHostsFile string
	Profile              profile.Profile
}

// PreflightReport is safe to record in operational logs. It contains no key
// material, command contents, or tunneled traffic.
type PreflightReport struct {
	Path               string
	SHA256             string
	Version            string
	Profile            string
	ArtifactProfileID  string
	OpenSSLVersion     string
	OpenSSLVersionText string
	OpenSSLLinkage     string
	ExecutableFormat   string
	DynamicLibraries   []string
}

// Equal compares all attested facts, including the ordered ELF dependency
// inventory. Reports deliberately do not rely on direct struct comparison so
// future slice-backed evidence cannot be omitted accidentally.
func (report PreflightReport) Equal(other PreflightReport) bool {
	return report.Path == other.Path &&
		report.SHA256 == other.SHA256 &&
		report.Version == other.Version &&
		report.Profile == other.Profile &&
		report.ArtifactProfileID == other.ArtifactProfileID &&
		report.OpenSSLVersion == other.OpenSSLVersion &&
		report.OpenSSLVersionText == other.OpenSSLVersionText &&
		report.OpenSSLLinkage == other.OpenSSLLinkage &&
		report.ExecutableFormat == other.ExecutableFormat &&
		slices.Equal(report.DynamicLibraries, other.DynamicLibraries)
}

type clientPreflightDependencies struct {
	runner             clientCommandRunner
	inspector          executableInspector
	environment        func() []string
	ownershipChecker   fileOwnershipChecker
	requireFixedLayout bool
	artifactProfileID  artifactprofile.ID
	resolveArtifact    func() (artifactprofile.Profile, error)
}

func productionClientPreflightDependencies() clientPreflightDependencies {
	return clientPreflightDependencies{
		runner:             execClientCommandRunner{},
		inspector:          productionExecutableInspector(),
		environment:        os.Environ,
		ownershipChecker:   fileInfoOwnedByRoot,
		requireFixedLayout: true,
		resolveArtifact:    artifactprofile.Current,
	}
}

// Preflight verifies the pinned executable and the exact algorithms required
// by the selected profile before any network connection is attempted.
func Preflight(ctx context.Context, binary Binary, selected profile.Profile) (PreflightReport, error) {
	return preflightWithDependencies(ctx, binary, selected, productionClientPreflightDependencies())
}

func preflightWithDependencies(
	ctx context.Context,
	binary Binary,
	selected profile.Profile,
	dependencies clientPreflightDependencies,
) (PreflightReport, error) {
	if dependencies.environment == nil {
		return PreflightReport{}, errors.New("OpenSSH preflight environment provider is required")
	}
	environment := sanitizedClientEnvironment(dependencies.environment())
	return preflightWithEnvironment(ctx, binary, selected, dependencies, environment)
}

func preflightWithEnvironment(
	ctx context.Context,
	binary Binary,
	selected profile.Profile,
	dependencies clientPreflightDependencies,
	environment []string,
) (PreflightReport, error) {
	if ctx == nil {
		return PreflightReport{}, errors.New("OpenSSH preflight context is required")
	}
	if dependencies.runner == nil {
		return PreflightReport{}, errors.New("OpenSSH preflight command runner is required")
	}
	if dependencies.inspector == nil {
		return PreflightReport{}, errors.New("OpenSSH preflight executable inspector is required")
	}
	if dependencies.requireFixedLayout && dependencies.ownershipChecker == nil {
		return PreflightReport{}, errors.New("OpenSSH preflight ownership checker is required")
	}
	if err := validateRegisteredProfile(selected); err != nil {
		return PreflightReport{}, err
	}
	if !filepath.IsAbs(binary.Path) {
		return PreflightReport{}, errors.New("OpenSSH binary path must be absolute")
	}
	if filepath.Clean(binary.Path) != binary.Path {
		return PreflightReport{}, errors.New("OpenSSH binary path must be clean")
	}
	if !isLowerHexSHA256(binary.SHA256) {
		return PreflightReport{}, errors.New("OpenSSH binary SHA-256 must contain exactly 64 lowercase hexadecimal characters")
	}

	artifactProfileID := dependencies.artifactProfileID
	expectedFormat := selected.ExecutableFormat
	var heldLayout *heldClientLayout
	if dependencies.requireFixedLayout {
		if dependencies.resolveArtifact == nil {
			return PreflightReport{}, errors.New("OpenSSH preflight artifact-profile resolver is required")
		}
		artifactProfile, err := dependencies.resolveArtifact()
		if err != nil {
			return PreflightReport{}, err
		}
		if err := requireProductionClientPlatform(); err != nil {
			return PreflightReport{}, err
		}
		if artifactProfile.OpenSSLLinkage != selected.OpenSSLLinkage {
			return PreflightReport{}, fmt.Errorf(
				"artifact profile %q OpenSSL linkage %q does not match wire profile requirement %q",
				artifactProfile.ID,
				artifactProfile.OpenSSLLinkage,
				selected.OpenSSLLinkage,
			)
		}
		if artifactProfile.Layout.SSHPath == "" {
			return PreflightReport{}, fmt.Errorf(
				"artifact profile %q does not define a fixed OpenSSH path",
				artifactProfile.ID,
			)
		}
		if binary.Path != artifactProfile.Layout.SSHPath {
			return PreflightReport{}, fmt.Errorf(
				"OpenSSH binary path %q is outside artifact profile %q fixed layout",
				binary.Path,
				artifactProfile.ID,
			)
		}
		if artifactProfile.ExecutableFormat == "" {
			return PreflightReport{}, fmt.Errorf(
				"artifact profile %q does not define an executable format",
				artifactProfile.ID,
			)
		}
		expectedFormat = artifactProfile.ExecutableFormat
		artifactProfileID = artifactProfile.ID
		var layoutErr error
		heldLayout, layoutErr = holdProductionClientLayoutAt(
			binary.Path,
			artifactProfile.Layout.SSHPath,
			dependencies.ownershipChecker,
		)
		if layoutErr != nil {
			return PreflightReport{}, layoutErr
		}
		defer heldLayout.close()
		if err := heldLayout.verify(); err != nil {
			return PreflightReport{}, err
		}
		if err := verifyProductionClientCodeSignature(binary.Path); err != nil {
			return PreflightReport{}, err
		}
	}

	initial, err := inspectClientExecutable(
		binary,
		dependencies.inspector,
		dependencies.requireFixedLayout,
		dependencies.ownershipChecker,
	)
	if err != nil {
		return PreflightReport{}, err
	}
	if heldLayout != nil {
		if err := heldLayout.verify(); err != nil {
			return PreflightReport{}, err
		}
	}
	if initial.linkage.format != expectedFormat {
		return PreflightReport{}, fmt.Errorf(
			"OpenSSH executable format %q does not match profile requirement %q",
			initial.linkage.format,
			expectedFormat,
		)
	}
	if initial.linkage.openSSLLinkage != selected.OpenSSLLinkage {
		return PreflightReport{}, fmt.Errorf(
			"OpenSSH OpenSSL linkage %q does not match profile requirement %q",
			initial.linkage.openSSLLinkage,
			selected.OpenSSLLinkage,
		)
	}

	versionOutput, err := dependencies.runner.Run(ctx, binary.Path, environment, "-V")
	if err != nil {
		return PreflightReport{}, fmt.Errorf("query OpenSSH version: %w", err)
	}
	if err := validateOpenSSHVersionOutput(versionOutput, selected); err != nil {
		return PreflightReport{}, err
	}

	checks := []struct {
		query    string
		required []string
	}{
		{query: "kex", required: []string{selected.KeyExchangeAlgorithm}},
		{query: "key", required: []string{selected.AuthenticationKeyType}},
		{query: "sig", required: []string{selected.AuthenticationKeyType}},
		{query: "cipher", required: selected.Ciphers},
	}
	for _, check := range checks {
		output, queryErr := dependencies.runner.Run(ctx, binary.Path, environment, "-Q", check.query)
		if queryErr != nil {
			return PreflightReport{}, fmt.Errorf("query OpenSSH %s algorithms: %w", check.query, queryErr)
		}
		if len(output.stderr) != 0 {
			return PreflightReport{}, fmt.Errorf(
				"OpenSSH %s algorithm query wrote unexpected stderr %q",
				check.query,
				output.stderr,
			)
		}
		supported, linesErr := outputLines(output.stdout)
		if linesErr != nil {
			return PreflightReport{}, fmt.Errorf("parse OpenSSH %s algorithms: %w", check.query, linesErr)
		}
		for _, required := range check.required {
			if !slices.Contains(supported, required) {
				return PreflightReport{}, fmt.Errorf("OpenSSH does not support required %s algorithm %q", check.query, required)
			}
		}
	}

	final, err := inspectClientExecutable(
		binary,
		dependencies.inspector,
		dependencies.requireFixedLayout,
		dependencies.ownershipChecker,
	)
	if err != nil {
		return PreflightReport{}, err
	}
	if heldLayout != nil {
		if err := heldLayout.verify(); err != nil {
			return PreflightReport{}, err
		}
	}
	if !os.SameFile(initial.info, final.info) || initial.sha256 != final.sha256 ||
		initial.info.Size() != final.info.Size() ||
		!initial.info.ModTime().Equal(final.info.ModTime()) ||
		!initial.linkage.equal(final.linkage) {
		return PreflightReport{}, errors.New("OpenSSH binary changed during preflight")
	}

	return PreflightReport{
		Path:               binary.Path,
		SHA256:             initial.sha256,
		Version:            selected.EngineVersion,
		Profile:            selected.ID,
		ArtifactProfileID:  string(artifactProfileID),
		OpenSSLVersion:     selected.OpenSSLVersion,
		OpenSSLVersionText: selected.OpenSSLVersionText,
		OpenSSLLinkage:     initial.linkage.openSSLLinkage,
		ExecutableFormat:   initial.linkage.format,
		DynamicLibraries:   append([]string{}, initial.linkage.dynamicLibraries...),
	}, nil
}

type clientOption struct {
	name            string
	values          []string
	effectiveValues []string
	expectEffective bool
}

type clientPolicy struct {
	options []clientOption
}

// RenderClientConfig returns a human-inspectable SSH-config representation of
// the exact closed policy. It is diagnostic output only and is never written
// or accepted as runtime authority. Execution uses -F none and supplies every
// option from this same ordered source.
func RenderClientConfig(spec ClientSpec) (string, error) {
	policy, err := newClientPolicy(spec, "")
	if err != nil {
		return "", err
	}

	var output strings.Builder
	output.WriteString("# WarpTweet policy view. Runtime execution uses closed -o arguments.\n")
	output.WriteString("Host " + hostAlias + "\n")
	for _, option := range policy.options {
		fmt.Fprintf(&output, "    %s %s\n", option.name, renderConfigTokens(option.values))
	}

	return output.String(), nil
}

// Arguments returns the exact closed invocation. Execution disables all
// ambient configuration with -F none and admits no caller-provided options.
func Arguments(spec ClientSpec) ([]string, error) {
	policy, err := newClientPolicy(spec, "")
	if err != nil {
		return nil, err
	}
	return clientPolicyArguments(policy), nil
}

func newClientPolicy(spec ClientSpec, controlPath string) (clientPolicy, error) {
	if err := validateClientSpec(spec); err != nil {
		return clientPolicy{}, err
	}
	if controlPath != "" {
		if err := validateControlPath(controlPath); err != nil {
			return clientPolicy{}, err
		}
	}

	controlMaster := "no"
	controlMasterEffective := "false"
	controlPathOption := clientOption{name: "ControlPath", values: []string{"none"}}
	if controlPath != "" {
		controlMaster = "yes"
		controlMasterEffective = "true"
		controlPathOption = expectedClientOption("ControlPath", controlPath, controlPath)
	}

	options := []clientOption{
		expectedClientOption("HostName", spec.ServerAddress.String(), spec.ServerAddress.String()),
		expectedClientOption("Port", fmt.Sprintf("%d", spec.ServerPort), fmt.Sprintf("%d", spec.ServerPort)),
		expectedClientOption("User", spec.ServerUser, spec.ServerUser),
		expectedClientOption("HostKeyAlias", "warptweet-"+spec.TunnelID, "warptweet-"+spec.TunnelID),
		expectedClientOption("KexAlgorithms", spec.Profile.KeyExchangeAlgorithm, spec.Profile.KeyExchangeAlgorithm),
		expectedClientOption("HostKeyAlgorithms", spec.Profile.AuthenticationKeyType, spec.Profile.AuthenticationKeyType),
		expectedClientOption("PubkeyAcceptedAlgorithms", spec.Profile.AuthenticationKeyType, spec.Profile.AuthenticationKeyType),
		expectedClientOption("Ciphers", strings.Join(spec.Profile.Ciphers, ","), strings.Join(spec.Profile.Ciphers, ",")),
		expectedClientOption("Compression", "no", "no"),
		expectedClientOption("BatchMode", "yes", "yes"),
		expectedClientOption("PreferredAuthentications", "publickey", "publickey"),
		expectedClientOption("PubkeyAuthentication", "yes", "true"),
		expectedClientOption("PasswordAuthentication", "no", "no"),
		expectedClientOption("KbdInteractiveAuthentication", "no", "no"),
		expectedClientOption("HostbasedAuthentication", "no", "no"),
		expectedClientOption("IdentitiesOnly", "yes", "yes"),
		expectedClientOption("IdentityAgent", "none", "none"),
		expectedClientOption("AddKeysToAgent", "no", "false"),
		expectedClientOption("IdentityFile", spec.IdentityFile, spec.IdentityFile),
		expectedClientOption("StrictHostKeyChecking", "yes", "true"),
		expectedClientOption("UserKnownHostsFile", spec.KnownHostsFile, spec.KnownHostsFile),
		expectedClientOption("GlobalKnownHostsFile", spec.GlobalKnownHostsFile, spec.GlobalKnownHostsFile),
		{name: "KnownHostsCommand", values: []string{"none"}},
		expectedClientOption("UpdateHostKeys", "no", "false"),
		expectedClientOption("VerifyHostKeyDNS", "no", "false"),
		expectedClientOption("CheckHostIP", "no", "no"),
		expectedClientOption("CanonicalizeHostname", "no", "false"),
		expectedClientOption("HashKnownHosts", "no", "no"),
		expectedClientOption("ForwardAgent", "no", "no"),
		expectedClientOption("ForwardX11", "no", "no"),
		expectedClientOption("GatewayPorts", "no", "no"),
		expectedClientOption("RequestTTY", "no", "false"),
		expectedClientOption("SessionType", "none", "none"),
		expectedClientOption("StdinNull", "yes", "yes"),
		expectedClientOption("EscapeChar", "none", "none"),
		expectedClientOption("EnableEscapeCommandline", "no", "no"),
		expectedClientOption("PermitLocalCommand", "no", "no"),
		{name: "ProxyCommand", values: []string{"none"}},
		{name: "ProxyJump", values: []string{"none"}},
		expectedClientOption("ProxyUseFdpass", "no", "no"),
		expectedClientOption("ControlMaster", controlMaster, controlMasterEffective),
		controlPathOption,
		expectedClientOption("ControlPersist", "no", "no"),
		expectedClientOption("ForkAfterAuthentication", "no", "no"),
		expectedClientOption("ExitOnForwardFailure", "yes", "yes"),
		expectedClientOption("ClearAllForwardings", "no", "no"),
		expectedClientOption("ConnectionAttempts", "1", "1"),
		expectedClientOption("ConnectTimeout", "15", "15"),
		expectedClientOption("ServerAliveInterval", "15", "15"),
		expectedClientOption("ServerAliveCountMax", "3", "3"),
		expectedClientOption("TCPKeepAlive", "no", "no"),
		{
			name:            "RekeyLimit",
			values:          []string{"512M", "1h"},
			effectiveValues: []string{"536870912 3600"},
			expectEffective: true,
		},
		expectedClientOption("LogLevel", "VERBOSE", "VERBOSE"),
		// These typed options are the direct ssh_config equivalents of -N,
		// -T, and -L. Keeping them here makes rendered policy, executable argv,
		// and effective-policy attestation share one source of truth.
		{
			name: "LocalForward",
			values: []string{
				fmt.Sprintf("[%s]:%d", spec.ListenAddress.Unmap(), spec.ListenPort),
				fmt.Sprintf("[%s]:%d", spec.TargetAddress.Unmap(), spec.TargetPort),
			},
			effectiveValues: []string{effectiveLocalForward(spec)},
			expectEffective: true,
		},
		expectedClientOption("Tunnel", "no", "false"),
		expectedClientOption("TunnelDevice", "any:any", "any:any"),
	}
	return clientPolicy{options: options}, nil
}

func expectedClientOption(name, value, effectiveValue string) clientOption {
	return clientOption{
		name:            name,
		values:          []string{value},
		effectiveValues: []string{effectiveValue},
		expectEffective: true,
	}
}

func renderConfigTokens(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = quoteConfig(value)
	}
	return strings.Join(quoted, " ")
}

func renderArgumentTokens(values []string) string {
	// execve already preserves each -o argument as one argv element. Adding
	// ssh_config quotes here would not provide shell grouping: OpenSSH would
	// parse the quote bytes as part of the value. The validated policy values
	// exclude line and NUL controls, and multi-token directives intentionally
	// retain one literal ASCII-space separator inside this argv element.
	return strings.Join(values, " ")
}

func clientPolicyArguments(policy clientPolicy) []string {
	arguments := make([]string, 0, 3+len(policy.options)*2)
	arguments = append(arguments, "-F", "none")
	for _, option := range policy.options {
		arguments = append(
			arguments,
			"-o",
			option.name+"="+renderArgumentTokens(option.values),
		)
	}
	return append(arguments, hostAlias)
}

func validateClientSpec(spec ClientSpec) error {
	if spec.Profile.ID == "" {
		return errors.New("cryptographic profile is required")
	}
	if err := config.ValidateTunnelID(spec.TunnelID); err != nil {
		return fmt.Errorf("invalid tunnel ID: %w", err)
	}
	if err := validateRegisteredProfile(spec.Profile); err != nil {
		return err
	}
	if !spec.ServerAddress.IsValid() || !spec.TargetAddress.IsValid() {
		return errors.New("server and target addresses must be numeric IP addresses")
	}
	if spec.ListenAddress.String() != "127.0.0.1" {
		return errors.New("listener must bind exactly to 127.0.0.1")
	}
	if spec.ServerPort == 0 || spec.ListenPort == 0 || spec.TargetPort == 0 {
		return errors.New("server, listener, and target ports must be non-zero")
	}
	for field, value := range map[string]string{
		"server user":             spec.ServerUser,
		"identity file":           spec.IdentityFile,
		"known hosts file":        spec.KnownHostsFile,
		"global known hosts file": spec.GlobalKnownHostsFile,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", field)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s contains a forbidden control character", field)
		}
	}
	for field, value := range map[string]string{
		"identity file":           spec.IdentityFile,
		"known hosts file":        spec.KnownHostsFile,
		"global known hosts file": spec.GlobalKnownHostsFile,
	} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s must be absolute", field)
		}
	}
	return nil
}

func validateRegisteredProfile(selected profile.Profile) error {
	registered, err := profile.Lookup(selected.ID)
	if err != nil {
		return err
	}
	if registered.EngineVersion != selected.EngineVersion ||
		registered.OpenSSLVersion != selected.OpenSSLVersion ||
		registered.OpenSSLVersionText != selected.OpenSSLVersionText ||
		registered.OpenSSLLinkage != selected.OpenSSLLinkage ||
		registered.ExecutableFormat != selected.ExecutableFormat ||
		registered.KeyExchangeAlgorithm != selected.KeyExchangeAlgorithm ||
		registered.AuthenticationKeyType != selected.AuthenticationKeyType ||
		registered.RawPublicKeyBytes != selected.RawPublicKeyBytes ||
		registered.RawSignatureBytes != selected.RawSignatureBytes ||
		registered.AuthenticationBindingStatus != selected.AuthenticationBindingStatus ||
		registered.SupportStatus != selected.SupportStatus ||
		!slices.Equal(registered.Ciphers, selected.Ciphers) {
		return errors.New("cryptographic profile does not match its immutable registry entry")
	}
	return nil
}

func quoteConfig(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"")
	return "\"" + replacer.Replace(value) + "\""
}

type clientExecutableSnapshot struct {
	info    os.FileInfo
	sha256  string
	linkage executableLinkageReport
}

func inspectClientExecutable(
	binary Binary,
	inspector executableInspector,
	requireRootOwnership bool,
	ownershipChecker fileOwnershipChecker,
) (clientExecutableSnapshot, error) {
	pathInfo, err := os.Lstat(binary.Path)
	if err != nil {
		return clientExecutableSnapshot{}, fmt.Errorf("inspect OpenSSH binary: %w", err)
	}
	if err := validateClientExecutableInfo(
		pathInfo,
		requireRootOwnership,
		true,
		ownershipChecker,
	); err != nil {
		return clientExecutableSnapshot{}, err
	}

	file, err := os.Open(binary.Path)
	if err != nil {
		return clientExecutableSnapshot{}, fmt.Errorf("open OpenSSH binary for attestation: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return clientExecutableSnapshot{}, fmt.Errorf("inspect opened OpenSSH binary: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) || !openedInfo.Mode().IsRegular() {
		return clientExecutableSnapshot{}, errors.New("OpenSSH binary changed while it was opened for attestation")
	}
	if err := validateClientExecutableInfo(
		openedInfo,
		requireRootOwnership,
		false,
		ownershipChecker,
	); err != nil {
		return clientExecutableSnapshot{}, err
	}

	digest, err := hashClientExecutable(file)
	if err != nil {
		return clientExecutableSnapshot{}, err
	}
	if digest != binary.SHA256 {
		return clientExecutableSnapshot{}, fmt.Errorf("OpenSSH binary SHA-256 mismatch: got %s", digest)
	}
	linkage, err := inspector.Inspect(file)
	if err != nil {
		return clientExecutableSnapshot{}, err
	}
	finalDigest, err := hashClientExecutable(file)
	if err != nil {
		return clientExecutableSnapshot{}, fmt.Errorf("rehash OpenSSH binary after linkage inspection: %w", err)
	}
	finalOpenedInfo, err := file.Stat()
	if err != nil {
		return clientExecutableSnapshot{}, fmt.Errorf("reinspect opened OpenSSH binary: %w", err)
	}
	finalPathInfo, err := os.Lstat(binary.Path)
	if err != nil {
		return clientExecutableSnapshot{}, fmt.Errorf("reinspect OpenSSH binary path: %w", err)
	}
	if finalPathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(openedInfo, finalOpenedInfo) || !os.SameFile(openedInfo, finalPathInfo) {
		return clientExecutableSnapshot{}, errors.New("OpenSSH binary changed during executable attestation")
	}
	if finalDigest != digest || finalDigest != binary.SHA256 ||
		openedInfo.Size() != finalOpenedInfo.Size() ||
		openedInfo.Size() != finalPathInfo.Size() ||
		!openedInfo.ModTime().Equal(finalOpenedInfo.ModTime()) ||
		!openedInfo.ModTime().Equal(finalPathInfo.ModTime()) {
		return clientExecutableSnapshot{}, errors.New("OpenSSH binary content or metadata changed during executable attestation")
	}
	if err := validateClientExecutableInfo(
		finalOpenedInfo,
		requireRootOwnership,
		false,
		ownershipChecker,
	); err != nil {
		return clientExecutableSnapshot{}, err
	}
	if err := validateClientExecutableInfo(
		finalPathInfo,
		requireRootOwnership,
		true,
		ownershipChecker,
	); err != nil {
		return clientExecutableSnapshot{}, err
	}
	return clientExecutableSnapshot{info: finalPathInfo, sha256: digest, linkage: linkage}, nil
}

func hashClientExecutable(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek OpenSSH binary for hashing: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash OpenSSH binary: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validateClientExecutableInfo(
	info os.FileInfo,
	requireRootOwnership bool,
	rejectSymlink bool,
	ownershipChecker fileOwnershipChecker,
) error {
	if rejectSymlink && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("OpenSSH binary must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("OpenSSH binary must be a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("OpenSSH binary is not executable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("OpenSSH binary must not be group or world writable")
	}
	if requireRootOwnership {
		if ownershipChecker == nil {
			return errors.New("OpenSSH binary ownership checker is required")
		}
		owned, err := ownershipChecker(info)
		if err != nil {
			return fmt.Errorf("inspect OpenSSH binary ownership: %w", err)
		}
		if !owned {
			return errors.New("OpenSSH binary must be owned by root")
		}
	}
	return nil
}

func outputLines(output []byte) ([]string, error) {
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != '\n' {
		return nil, errors.New("algorithm output must be LF-terminated")
	}
	rawLines := bytes.Split(output[:len(output)-1], []byte{'\n'})
	lines := make([]string, 0, len(rawLines))
	for _, rawLine := range rawLines {
		line := string(rawLine)
		if line == "" || strings.TrimSpace(line) != line || strings.ContainsAny(line, "\r\x00") {
			return nil, fmt.Errorf("algorithm output contains malformed line %q", rawLine)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func validateOpenSSHVersionOutput(output clientCommandOutput, selected profile.Profile) error {
	if len(output.stdout) != 0 {
		return fmt.Errorf("OpenSSH -V wrote unexpected stdout %q", output.stdout)
	}
	expected := []byte(selected.EngineVersion + ", " + selected.OpenSSLVersionText + "\n")
	if !bytes.Equal(output.stderr, expected) {
		return fmt.Errorf(
			"OpenSSH -V stderr is %q, want exact profile output %q",
			output.stderr,
			expected,
		)
	}
	return nil
}
