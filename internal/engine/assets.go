package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/sshwire"
)

const maxTrustFileBytes = 1 << 20

var knownHostsAliasPattern = regexp.MustCompile(`^warptweet-[a-z][a-z0-9_-]{0,63}$`)

// AssetReport records non-secret trust inputs proven before launch.
type AssetReport struct {
	HostKeyAlias string
	HostKeyPins  int
}

// ValidateAssets verifies filesystem and host-pin invariants that OpenSSH
// configuration alone cannot express.
func ValidateAssets(spec ClientSpec) (AssetReport, error) {
	dependencies, err := productionClientAssetDependencies()
	if err != nil {
		return AssetReport{}, err
	}
	return validateAssetsWithDependencies(spec, dependencies)
}

func validateAssetsWithDependencies(
	spec ClientSpec,
	dependencies clientAssetDependencies,
) (AssetReport, error) {
	if spec.IdentityFile != dependencies.layout.identityPath && !isRouteGenerationAsset(spec.IdentityFile, "identity") {
		return AssetReport{}, fmt.Errorf(
			"production client identity path must be exactly %q or a reserved route generation",
			dependencies.layout.identityPath,
		)
	}
	if spec.KnownHostsFile != dependencies.layout.knownHostsPath && !isRouteGenerationAsset(spec.KnownHostsFile, "known_hosts") {
		return AssetReport{}, fmt.Errorf(
			"production client known-hosts path must be exactly %q or a reserved route generation",
			dependencies.layout.knownHostsPath,
		)
	}
	if spec.GlobalKnownHostsFile != dependencies.layout.globalKnownHostsPath && !isRouteGenerationAsset(spec.GlobalKnownHostsFile, "known_hosts.empty") {
		return AssetReport{}, fmt.Errorf(
			"production client global known-hosts path must be exactly %q or a reserved route generation",
			dependencies.layout.globalKnownHostsPath,
		)
	}

	serviceIdentity, err := resolveClientServiceIdentity(dependencies)
	if err != nil {
		return AssetReport{}, err
	}
	identity, err := openClientStateFile(
		dependencies,
		serviceIdentity,
		spec.IdentityFile,
		identityClientNodePolicy(),
	)
	if err != nil {
		return AssetReport{}, err
	}
	defer identity.file.Close()
	knownHosts, err := openClientStateFile(
		dependencies,
		serviceIdentity,
		spec.KnownHostsFile,
		knownHostsClientNodePolicy(),
	)
	if err != nil {
		return AssetReport{}, err
	}
	defer knownHosts.file.Close()
	globalKnownHosts, err := openClientStateFile(
		dependencies,
		serviceIdentity,
		spec.GlobalKnownHostsFile,
		globalKnownHostsClientNodePolicy(),
	)
	if err != nil {
		return AssetReport{}, err
	}
	defer globalKnownHosts.file.Close()

	knownHostsContents, err := readBoundedClientStateFile(
		knownHosts.file,
		maxTrustFileBytes,
		"known-hosts file",
	)
	if err != nil {
		return AssetReport{}, err
	}
	globalKnownHostsContents, err := readBoundedClientStateFile(
		globalKnownHosts.file,
		maxTrustFileBytes,
		"global known-hosts file",
	)
	if err != nil {
		return AssetReport{}, err
	}
	if len(globalKnownHostsContents) != 0 {
		return AssetReport{}, errors.New("global known-hosts file must be empty; all trust belongs in the per-tunnel pin store")
	}

	alias := "warptweet-" + spec.TunnelID
	pins, err := countHostPins(
		bytes.NewReader(knownHostsContents),
		alias,
		spec.Profile.AuthenticationKeyType,
		spec.Profile.RawPublicKeyBytes,
	)
	if err != nil {
		return AssetReport{}, err
	}
	if pins == 0 {
		return AssetReport{}, fmt.Errorf("known-hosts file contains no %s pin for alias %q", spec.Profile.AuthenticationKeyType, alias)
	}

	if dependencies.hooks.afterInitialOpen != nil {
		dependencies.hooks.afterInitialOpen()
	}
	verifiedIdentity, err := verifyOpenedClientStateFile(dependencies, serviceIdentity, identity)
	if err != nil {
		return AssetReport{}, err
	}
	defer verifiedIdentity.file.Close()
	verifiedKnownHosts, err := verifyOpenedClientStateFile(dependencies, serviceIdentity, knownHosts)
	if err != nil {
		return AssetReport{}, err
	}
	defer verifiedKnownHosts.file.Close()
	verifiedGlobalKnownHosts, err := verifyOpenedClientStateFile(
		dependencies,
		serviceIdentity,
		globalKnownHosts,
	)
	if err != nil {
		return AssetReport{}, err
	}
	defer verifiedGlobalKnownHosts.file.Close()

	verifiedKnownHostsContents, err := readBoundedClientStateFile(
		verifiedKnownHosts.file,
		maxTrustFileBytes,
		"known-hosts file",
	)
	if err != nil {
		return AssetReport{}, err
	}
	verifiedGlobalKnownHostsContents, err := readBoundedClientStateFile(
		verifiedGlobalKnownHosts.file,
		maxTrustFileBytes,
		"global known-hosts file",
	)
	if err != nil {
		return AssetReport{}, err
	}
	if !bytes.Equal(knownHostsContents, verifiedKnownHostsContents) ||
		!bytes.Equal(globalKnownHostsContents, verifiedGlobalKnownHostsContents) {
		return AssetReport{}, errors.New("client trust files changed during fixed-layout validation")
	}
	if dependencies.hooks.beforeFinalVerify != nil {
		dependencies.hooks.beforeFinalVerify()
	}
	finalIdentity, err := verifyOpenedClientStateFile(dependencies, serviceIdentity, verifiedIdentity)
	if err != nil {
		return AssetReport{}, err
	}
	defer finalIdentity.file.Close()
	finalKnownHosts, err := verifyOpenedClientStateFile(
		dependencies,
		serviceIdentity,
		verifiedKnownHosts,
	)
	if err != nil {
		return AssetReport{}, err
	}
	defer finalKnownHosts.file.Close()
	finalGlobalKnownHosts, err := verifyOpenedClientStateFile(
		dependencies,
		serviceIdentity,
		verifiedGlobalKnownHosts,
	)
	if err != nil {
		return AssetReport{}, err
	}
	defer finalGlobalKnownHosts.file.Close()
	finalKnownHostsContents, err := readBoundedClientStateFile(
		finalKnownHosts.file,
		maxTrustFileBytes,
		"known-hosts file",
	)
	if err != nil {
		return AssetReport{}, err
	}
	finalGlobalKnownHostsContents, err := readBoundedClientStateFile(
		finalGlobalKnownHosts.file,
		maxTrustFileBytes,
		"global known-hosts file",
	)
	if err != nil {
		return AssetReport{}, err
	}
	if !bytes.Equal(knownHostsContents, finalKnownHostsContents) ||
		!bytes.Equal(globalKnownHostsContents, finalGlobalKnownHostsContents) {
		return AssetReport{}, errors.New("client trust files changed during final fixed-layout validation")
	}
	return AssetReport{HostKeyAlias: alias, HostKeyPins: pins}, nil
}

func countHostPins(reader io.Reader, alias, algorithm string, rawPublicKeyBytes int) (int, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maxTrustFileBytes+1))
	if err != nil {
		return 0, fmt.Errorf("read known-hosts file: %w", err)
	}
	if len(contents) > maxTrustFileBytes {
		return 0, fmt.Errorf("known-hosts file exceeds %d bytes", maxTrustFileBytes)
	}
	if len(contents) == 0 {
		return 0, nil
	}
	if contents[len(contents)-1] != '\n' {
		return 0, errors.New("known-hosts file must end with an LF")
	}
	lines := bytes.Split(contents[:len(contents)-1], []byte{'\n'})
	pins := 0
	for _, rawLine := range lines {
		line := string(rawLine)
		if line == "" {
			return 0, fmt.Errorf("known-hosts file contains a blank or comment-only entry")
		}
		for index, value := range []byte(line) {
			if value < 0x20 || value == 0x7f {
				return 0, fmt.Errorf("known-hosts file contains a control character at byte %d", index)
			}
		}
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[3] != knownhosts.ManagedHostComment {
			return 0, fmt.Errorf("known-hosts file contains an unmanaged entry")
		}
		canonical := strings.Join(fields, " ")
		if line != canonical {
			return 0, fmt.Errorf("known-hosts file contains a non-canonical entry")
		}
		if strings.HasPrefix(fields[0], "@") {
			return 0, fmt.Errorf("known-hosts markers are not permitted in the WarpTweet pin store")
		}
		if fields[1] != algorithm {
			return 0, fmt.Errorf("known-hosts file includes forbidden key type %q", fields[1])
		}
		if err := sshwire.ValidatePublicKeyBlob(fields[2], algorithm, rawPublicKeyBytes); err != nil {
			return 0, err
		}
		if !knownHostsAliasPattern.MatchString(fields[0]) {
			return 0, fmt.Errorf("known-hosts entry uses forbidden host alias %q", fields[0])
		}
		if fields[0] != alias {
			continue
		}
		pins++
	}
	return pins, nil
}
