package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/installlayout"
)

// ClientLaunch is an exact OpenSSH command and the non-secret attestation
// evidence established immediately before it may be executed.
type ClientLaunch struct {
	Path      string
	Args      []string
	Env       []string
	Preflight PreflightReport
	Assets    AssetReport
}

// ManagedClientLaunch is one fully attested foreground ControlMaster launch
// and its one-shot PID-bound authenticated-forward readiness witness.
type ManagedClientLaunch struct {
	ClientLaunch
	Readiness ClientReadiness
}

type clientLaunchDependencies struct {
	preflight      clientPreflightDependencies
	validateAssets func(ClientSpec) (AssetReport, error)
}

type managedClientLaunchDependencies struct {
	launch        clientLaunchDependencies
	runtimeRoot   string
	runner        readinessCommandRunner
	poll          time.Duration
	leafOwner     fileOwnershipChecker
	ancestorOwner fileOwnershipChecker
}

func productionClientLaunchDependencies() clientLaunchDependencies {
	return clientLaunchDependencies{
		preflight:      productionClientPreflightDependencies(),
		validateAssets: ValidateAssets,
	}
}

func productionManagedClientLaunchDependencies() managedClientLaunchDependencies {
	runtimeRoot := installlayout.ClientRuntimeRoot
	if selected, err := artifactprofile.Current(); err == nil && selected.Layout.ClientRuntimeRoot != "" {
		runtimeRoot = selected.Layout.ClientRuntimeRoot
	}
	return managedClientLaunchDependencies{
		launch:        productionClientLaunchDependencies(),
		runtimeRoot:   runtimeRoot,
		runner:        execReadinessCommandRunner{},
		poll:          defaultReadinessPollInterval,
		leafOwner:     fileInfoOwnedByEffectiveUser,
		ancestorOwner: fileInfoOwnedByRoot,
	}
}

// AttestClientLaunch revalidates every executable, trust, and effective-policy
// input needed for one process launch. Args is the exact closed argument slice
// passed to ssh -G and returned for immediate execution.
func AttestClientLaunch(
	ctx context.Context,
	binary Binary,
	spec ClientSpec,
) (ClientLaunch, error) {
	return attestClientLaunchWithDependencies(
		ctx,
		binary,
		spec,
		productionClientLaunchDependencies(),
	)
}

func attestClientLaunchWithDependencies(
	ctx context.Context,
	binary Binary,
	spec ClientSpec,
	dependencies clientLaunchDependencies,
) (ClientLaunch, error) {
	arguments, err := Arguments(spec)
	if err != nil {
		return ClientLaunch{}, fmt.Errorf("prepare client launch arguments: %w", err)
	}
	policy, err := newClientPolicy(spec, "")
	if err != nil {
		return ClientLaunch{}, fmt.Errorf("prepare client launch policy: %w", err)
	}
	return attestClientPolicyWithDependencies(ctx, binary, spec, policy, arguments, dependencies)
}

// AttestManagedClientLaunch prepares the production one-process tunnel launch.
// runtimeDirectory is not policy input: it must equal the fixed path derived
// from the validated tunnel ID. The directory is retained only for the private
// transient control socket and must already exist as a mode-0700 directory.
func AttestManagedClientLaunch(
	ctx context.Context,
	binary Binary,
	runtimeDirectory string,
	spec ClientSpec,
) (ManagedClientLaunch, error) {
	return attestManagedClientLaunchWithDependencies(
		ctx,
		binary,
		runtimeDirectory,
		spec,
		productionManagedClientLaunchDependencies(),
	)
}

func attestManagedClientLaunchWithDependencies(
	ctx context.Context,
	binary Binary,
	runtimeDirectory string,
	spec ClientSpec,
	dependencies managedClientLaunchDependencies,
) (ManagedClientLaunch, error) {
	if dependencies.runtimeRoot == "" {
		return ManagedClientLaunch{}, errors.New("managed client runtime root is required")
	}
	if dependencies.runner == nil {
		return ManagedClientLaunch{}, errors.New("managed client readiness runner is required")
	}
	if dependencies.poll <= 0 {
		return ManagedClientLaunch{}, errors.New("managed client readiness poll interval must be positive")
	}
	if dependencies.leafOwner == nil {
		return ManagedClientLaunch{}, errors.New("managed client leaf ownership checker is required")
	}
	if dependencies.ancestorOwner == nil {
		return ManagedClientLaunch{}, errors.New("managed client ancestor ownership checker is required")
	}
	policy, err := managedClientPolicyAtRoot(
		runtimeDirectory,
		spec,
		dependencies.runtimeRoot,
	)
	if err != nil {
		return ManagedClientLaunch{}, fmt.Errorf("prepare managed client policy: %w", err)
	}
	arguments := clientPolicyArguments(policy)
	launch, err := attestClientPolicyWithDependencies(
		ctx,
		binary,
		spec,
		policy,
		arguments,
		dependencies.launch,
	)
	if err != nil {
		return ManagedClientLaunch{}, err
	}
	control, err := prepareControlSocketWithOwners(
		runtimeDirectory,
		dependencies.leafOwner,
		dependencies.ancestorOwner,
	)
	if err != nil {
		return ManagedClientLaunch{}, fmt.Errorf("prepare managed OpenSSH control socket: %w", err)
	}
	return ManagedClientLaunch{
		ClientLaunch: launch,
		Readiness: newAuthenticatedForwardReadiness(
			binary.Path,
			launch.Env,
			control,
			dependencies.runner,
			dependencies.poll,
		),
	}, nil
}

func attestClientPolicyWithDependencies(
	ctx context.Context,
	binary Binary,
	spec ClientSpec,
	policy clientPolicy,
	arguments []string,
	dependencies clientLaunchDependencies,
) (ClientLaunch, error) {
	if dependencies.preflight.environment == nil {
		return ClientLaunch{}, errors.New("client launch environment provider is required")
	}
	if dependencies.validateAssets == nil {
		return ClientLaunch{}, errors.New("client launch asset validator is required")
	}
	environment := sanitizedClientEnvironment(dependencies.preflight.environment())

	initialPreflight, err := preflightWithEnvironment(
		ctx,
		binary,
		spec.Profile,
		dependencies.preflight,
		environment,
	)
	if err != nil {
		return ClientLaunch{}, fmt.Errorf("preflight client engine: %w", err)
	}
	assets, err := dependencies.validateAssets(spec)
	if err != nil {
		return ClientLaunch{}, fmt.Errorf("validate client launch assets: %w", err)
	}
	if err := validateEffectiveClientConfigWithEnvironment(
		ctx,
		binary.Path,
		arguments,
		policy,
		environment,
	); err != nil {
		return ClientLaunch{}, err
	}
	finalPreflight, err := preflightWithEnvironment(
		ctx,
		binary,
		spec.Profile,
		dependencies.preflight,
		environment,
	)
	if err != nil {
		return ClientLaunch{}, fmt.Errorf("final preflight client engine: %w", err)
	}
	if !initialPreflight.Equal(finalPreflight) {
		return ClientLaunch{}, errors.New("OpenSSH engine attestation changed during client launch preparation")
	}

	return ClientLaunch{
		Path:      binary.Path,
		Args:      append([]string(nil), arguments...),
		Env:       append([]string(nil), environment...),
		Preflight: finalPreflight,
		Assets:    assets,
	}, nil
}
