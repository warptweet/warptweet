// Package command implements WarpTweet's shell-free command-line boundary.
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/engine"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/lifecycle"
	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/routestate"
	"warptweet.com/warptweet/internal/server"
	"warptweet.com/warptweet/internal/supervisor"
	"warptweet.com/warptweet/internal/systemdnotify"
)

const (
	Version      = "0.1.0-rc.6"
	manifestSize = 1 << 20
)

type commandDependencies struct {
	loadProductionClientManifest func(string) (config.Config, error)
	preflightClient              func(context.Context, engine.Binary, profile.Profile) (engine.PreflightReport, error)
	validateClientAssets         func(engine.ClientSpec) (engine.AssetReport, error)
	validateEffectiveClient      func(context.Context, string, engine.ClientSpec) error
	attestManagedClient          func(context.Context, engine.Binary, string, engine.ClientSpec) (engine.ManagedClientLaunch, error)
	newServiceNotifier           func() (serviceNotifier, error)
	authorizeManagedRun          func() error
	openRouteStore               func() (routeStore, error)
	enroll                       func(context.Context, []string, io.Writer, io.Writer) error
	up                           func(context.Context, []string, io.Writer, io.Writer, commandDependencies) error
	repair                       func(context.Context, []string, io.Writer, io.Writer, commandDependencies) error
}

type routeStore interface {
	LoadTransaction(string) (routestate.Transaction, error)
	WriteTransaction(routestate.Transaction) error
}

type serviceNotifier interface {
	Ready(string) error
	Stopping(string) error
}

// synchronizedWriter preserves whole Write calls when the supervised OpenSSH
// process and the controller's structured logger share one diagnostic stream.
// os/exec may copy child output from a pipe on a separate goroutine whenever
// the destination is not an *os.File, so the command boundary cannot assume an
// arbitrary io.Writer is safe for concurrent use.
type synchronizedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *synchronizedWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.writer.Write(data)
}

func authorizeManagedTunnelRun(dependencies commandDependencies) error {
	if dependencies.authorizeManagedRun != nil {
		return dependencies.authorizeManagedRun()
	}
	return requireServiceManagedRun()
}

func managedRunUnauthorized() error {
	return errors.New("run is unit-only; invoke warptweet up <route> so the service manager starts the tunnel")
}

func productionCommandDependencies() commandDependencies {
	return commandDependencies{
		loadProductionClientManifest: engine.LoadProductionClientManifest,
		preflightClient:              engine.Preflight,
		validateClientAssets:         engine.ValidateAssets,
		validateEffectiveClient:      engine.ValidateEffectiveClientConfig,
		attestManagedClient:          engine.AttestManagedClientLaunch,
		newServiceNotifier: func() (serviceNotifier, error) {
			return systemdnotify.FromEnvironment(os.Getenv)
		},
		authorizeManagedRun: requireServiceManagedRun,
	}
}

// Run executes one CLI command and returns a process exit code.
func Run(ctx context.Context, arguments []string, _ io.Reader, stdout, stderr io.Writer) int {
	return runWithDependencies(
		ctx,
		arguments,
		stdout,
		stderr,
		productionCommandDependencies(),
	)
}

func runWithDependencies(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) int {
	if len(arguments) == 0 {
		writeUsage(stderr)
		return 2
	}

	var err error
	switch arguments[0] {
	case "version":
		err = runVersion(arguments[1:], stdout, stderr)
	case "profile":
		err = runProfile(arguments[1:], stdout, stderr)
	case "validate":
		err = runValidate(arguments[1:], stdout, stderr)
	case "render-client":
		err = runRenderClient(arguments[1:], stdout, stderr)
	case "render-server":
		err = runRenderServer(arguments[1:], stdout, stderr)
	case "render-authorized-key":
		err = runRenderAuthorizedKey(arguments[1:], stdout, stderr)
	case "render-known-host":
		err = runRenderKnownHost(arguments[1:], stdout, stderr)
	case "doctor":
		err = runDoctor(ctx, arguments[1:], stdout, stderr, dependencies)
	case "doctor-server":
		err = runDoctorServer(ctx, arguments[1:], stdout, stderr)
	case "run":
		err = runTunnel(ctx, arguments[1:], stdout, stderr, dependencies)
	case "host":
		err = runHost(ctx, arguments[1:], stdout, stderr)
	case "connect":
		err = runConnect(ctx, arguments[1:], stdout, stderr, dependencies)
	case "repair":
		err = runRepair(ctx, arguments[1:], stdout, stderr, dependencies)
	case "server":
		err = runServer(ctx, arguments[1:], stdout, stderr)
	case "enroll":
		err = runEnroll(ctx, arguments[1:], stdout, stderr)
	case "up":
		err = runUp(ctx, arguments[1:], stdout, stderr, dependencies)
	case "routes":
		err = runRoutes(arguments[1:], stdout, stderr)
	case "status":
		err = runStatus(arguments[1:], stdout, stderr)
	case "down":
		err = runDown(arguments[1:], stdout, stderr)
	case "reconcile":
		err = runReconcile(ctx, arguments[1:], stdout, stderr, dependencies)
	case "rotate":
		err = runRotate(ctx, arguments[1:], stdout, stderr)
	case "revoke":
		err = runRevokeTunnel(ctx, arguments[1:], stdout, stderr)
	case "uninstall":
		err = runUninstall(arguments[1:], stdout, stderr)
	case "help", "-h", "--help":
		writeUsage(stdout)
		return 0
	case "gateway":
		err = outcome.Replaced("gateway", "warptweet host --to <port|ip:port>")
	default:
		fmt.Fprintf(stderr, "warptweet: unknown command %q\n", arguments[0])
		writeUsage(stderr)
		return 2
	}
	if err != nil {
		classified := outcome.From(err)
		if wantsJSON(arguments) {
			if writeErr := writeJSON(stdout, classified.Object()); writeErr != nil {
				fmt.Fprintf(stderr, "warptweet: %v\n", writeErr)
			}
		}
		if classified.Code != outcome.CodeHelp {
			fmt.Fprintf(stderr, "warptweet: %s\n", classified.Error())
			if classified.Hint != "" {
				fmt.Fprintf(stderr, "%s\n", classified.Hint)
			}
		}
		return classified.ExitCode()
	}
	return 0
}

func wantsJSON(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "--json" {
			return true
		}
	}
	return false
}

func runVersion(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("version accepts no arguments")
	}
	_, err := fmt.Fprintf(stdout, "WarpTweet %s\n", Version)
	return err
}

func runProfile(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("profile accepts no arguments")
	}
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		return err
	}
	return writeJSON(stdout, struct {
		ID                          string   `json:"id"`
		EngineVersion               string   `json:"engine_version"`
		OpenSSLVersion              string   `json:"openssl_version"`
		OpenSSLVersionText          string   `json:"openssl_version_text"`
		OpenSSLLinkage              string   `json:"openssl_linkage"`
		ExecutableFormat            string   `json:"executable_format"`
		KEX                         string   `json:"key_exchange"`
		Authentication              string   `json:"authentication"`
		PublicKeyBytes              int      `json:"raw_public_key_bytes"`
		SignatureBytes              int      `json:"raw_signature_bytes"`
		Ciphers                     []string `json:"ciphers"`
		AuthenticationBindingStatus string   `json:"authentication_binding_status"`
		SupportStatus               string   `json:"support_status"`
	}{
		ID:                          selected.ID,
		EngineVersion:               selected.EngineVersion,
		OpenSSLVersion:              selected.OpenSSLVersion,
		OpenSSLVersionText:          selected.OpenSSLVersionText,
		OpenSSLLinkage:              selected.OpenSSLLinkage,
		ExecutableFormat:            selected.ExecutableFormat,
		KEX:                         selected.KeyExchangeAlgorithm,
		Authentication:              selected.AuthenticationKeyType,
		PublicKeyBytes:              selected.RawPublicKeyBytes,
		SignatureBytes:              selected.RawSignatureBytes,
		Ciphers:                     selected.Ciphers,
		AuthenticationBindingStatus: string(selected.AuthenticationBindingStatus),
		SupportStatus:               string(selected.SupportStatus),
	})
}

func runValidate(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("validate", stderr)
	manifestPath := onceStringFlag{name: "--config"}
	flags.Var(&manifestPath, "config", "absolute or relative path to a .wt manifest")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if manifestPath.value == "" {
		return errors.New("validate requires --config")
	}

	kind, err := detectManifestKind(manifestPath.value)
	if err != nil {
		return err
	}
	var profileID string
	switch kind {
	case config.ClientTunnelsKind:
		manifest, loadErr := config.Load(manifestPath.value)
		if loadErr != nil {
			return loadErr
		}
		profileID = manifest.ProfileID
	case server.ManifestKind:
		manifest, loadErr := server.Load(manifestPath.value)
		if loadErr != nil {
			return loadErr
		}
		profileID = manifest.ProfileID
	default:
		return fmt.Errorf("unsupported WarpTweet manifest kind %q", kind)
	}

	selected, err := profile.Lookup(profileID)
	if err != nil {
		return err
	}
	return writeJSON(stdout, struct {
		Status                      string `json:"status"`
		Kind                        string `json:"kind"`
		Profile                     string `json:"profile"`
		AuthenticationBindingStatus string `json:"authentication_binding_status"`
		SupportStatus               string `json:"support_status"`
	}{
		Status:                      "valid",
		Kind:                        kind,
		Profile:                     profileID,
		AuthenticationBindingStatus: string(selected.AuthenticationBindingStatus),
		SupportStatus:               string(selected.SupportStatus),
	})
}

func runRenderClient(arguments []string, stdout, stderr io.Writer) error {
	manifestPath, tunnelID, err := parseClientSelection("render-client", arguments, stderr)
	if err != nil {
		return err
	}
	manifest, err := config.Load(manifestPath)
	if err != nil {
		return err
	}
	spec, err := clientSpec(manifest, tunnelID, manifestPath)
	if err != nil {
		return err
	}
	contents, err := engine.RenderClientConfig(spec)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, contents)
	return err
}

func runRenderServer(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("render-server", stderr)
	manifestPath := onceStringFlag{name: "--config"}
	flags.Var(&manifestPath, "config", "path to a server-gateway .wt manifest")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if manifestPath.value == "" {
		return errors.New("render-server requires --config")
	}
	manifest, err := server.Load(manifestPath.value)
	if err != nil {
		return err
	}
	contents, err := server.Render(manifest)
	if err != nil {
		return err
	}
	_, err = stdout.Write(contents)
	return err
}

func runRenderAuthorizedKey(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("render-authorized-key", stderr)
	manifestPath := onceStringFlag{name: "--config"}
	publicKeyPath := onceStringFlag{name: "--public-key"}
	notAfter := onceStringFlag{name: "--not-after"}
	flags.Var(&manifestPath, "config", "path to a server-gateway .wt manifest")
	flags.Var(&publicKeyPath, "public-key", "path to one plain client public-key line")
	flags.Var(&notAfter, "not-after", "RFC 3339 UTC authorization expiry")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if manifestPath.value == "" || publicKeyPath.value == "" || notAfter.value == "" {
		return errors.New("render-authorized-key requires --config, --public-key, and --not-after")
	}

	manifest, err := server.Load(manifestPath.value)
	if err != nil {
		return err
	}
	publicKey, err := readPublicKeyFile(publicKeyPath.value)
	if err != nil {
		return err
	}
	expiry, err := grant.ParseUTC(notAfter.value)
	if err != nil {
		return fmt.Errorf("not-after: %w", err)
	}
	contents, err := server.RenderAuthorizedKey(manifest, publicKey, expiry)
	if err != nil {
		return err
	}
	_, err = stdout.Write(contents)
	return err
}

func runRenderKnownHost(arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("render-known-host", stderr)
	manifestPath := onceStringFlag{name: "--config"}
	tunnelID := onceStringFlag{name: "--tunnel"}
	publicKeyPath := onceStringFlag{name: "--public-key"}
	flags.Var(&manifestPath, "config", "path to a client-tunnels .wt manifest")
	flags.Var(&tunnelID, "tunnel", "ID of the tunnel whose host key is pinned")
	flags.Var(&publicKeyPath, "public-key", "path to one plain host public-key line")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if manifestPath.value == "" || tunnelID.value == "" || publicKeyPath.value == "" {
		return errors.New("render-known-host requires --config, --tunnel, and --public-key")
	}

	manifest, err := config.Load(manifestPath.value)
	if err != nil {
		return err
	}
	if _, err := clientSpec(manifest, tunnelID.value, manifestPath.value); err != nil {
		return err
	}
	publicKey, err := readHostPublicKeyFile(publicKeyPath.value)
	if err != nil {
		return err
	}
	contents, err := knownhosts.RenderManagedHost(tunnelID.value, publicKey)
	if err != nil {
		return err
	}
	_, err = stdout.Write(contents)
	return err
}

type clientDoctorOutput struct {
	Status                      string   `json:"status"`
	Tunnel                      string   `json:"tunnel"`
	Profile                     string   `json:"profile"`
	ArtifactProfileID           string   `json:"artifact_profile_id"`
	AuthenticationBindingStatus string   `json:"authentication_binding_status"`
	SupportStatus               string   `json:"support_status"`
	EngineVersion               string   `json:"engine_version"`
	EngineSHA256                string   `json:"engine_sha256"`
	OpenSSLVersion              string   `json:"openssl_version"`
	OpenSSLVersionText          string   `json:"openssl_version_text"`
	OpenSSLLinkage              string   `json:"openssl_linkage"`
	ExecutableFormat            string   `json:"executable_format"`
	ELFNeeded                   []string `json:"elf_needed"`
	HostKeyAlias                string   `json:"host_key_alias"`
	HostKeyPins                 int      `json:"host_key_pins"`
}

func runDoctor(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) error {
	if dependencies.loadProductionClientManifest == nil {
		return errors.New("production client manifest loader is required")
	}
	if dependencies.preflightClient == nil {
		return errors.New("client doctor preflight dependency is required")
	}
	if dependencies.validateClientAssets == nil {
		return errors.New("client doctor asset-validation dependency is required")
	}
	if dependencies.validateEffectiveClient == nil {
		return errors.New("client doctor effective-configuration dependency is required")
	}
	manifestPath, tunnelID, err := parseClientSelection("doctor", arguments, stderr)
	if err != nil {
		return err
	}
	manifest, err := dependencies.loadProductionClientManifest(manifestPath)
	if err != nil {
		return err
	}
	spec, err := clientSpec(manifest, tunnelID, manifestPath)
	if err != nil {
		return err
	}
	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	preflight, err := dependencies.preflightClient(ctx, engine.Binary{
		Path:   layout.SSHPath,
		SHA256: manifest.SSHBinarySHA256,
	}, spec.Profile)
	if err != nil {
		return err
	}
	assets, err := dependencies.validateClientAssets(spec)
	if err != nil {
		return err
	}
	if err := dependencies.validateEffectiveClient(
		ctx,
		layout.SSHPath,
		spec,
	); err != nil {
		return err
	}
	return writeJSON(stdout, clientDoctorOutput{
		Status:                      "preflight_ready",
		Tunnel:                      tunnelID,
		Profile:                     spec.Profile.ID,
		ArtifactProfileID:           preflight.ArtifactProfileID,
		AuthenticationBindingStatus: string(spec.Profile.AuthenticationBindingStatus),
		SupportStatus:               string(spec.Profile.SupportStatus),
		EngineVersion:               preflight.Version,
		EngineSHA256:                preflight.SHA256,
		OpenSSLVersion:              preflight.OpenSSLVersion,
		OpenSSLVersionText:          preflight.OpenSSLVersionText,
		OpenSSLLinkage:              preflight.OpenSSLLinkage,
		ExecutableFormat:            preflight.ExecutableFormat,
		ELFNeeded:                   append([]string{}, preflight.DynamicLibraries...),
		HostKeyAlias:                assets.HostKeyAlias,
		HostKeyPins:                 assets.HostKeyPins,
	})
}

type serverDoctorOutput struct {
	Status                      string `json:"status"`
	Role                        string `json:"role"`
	Profile                     string `json:"profile"`
	AuthenticationBindingStatus string `json:"authentication_binding_status"`
	SupportStatus               string `json:"support_status"`
	EngineVersion               string `json:"engine_version"`
	OpenSSLVersion              string `json:"openssl_version"`
	OpenSSLVersionText          string `json:"openssl_version_text"`
	OpenSSLLinkage              string `json:"openssl_linkage"`
	ExecutableFormat            string `json:"executable_format"`
	StaticLibcryptoSHA256       string `json:"static_libcrypto_sha256"`
	SSHDPath                    string `json:"sshd_path"`
	SSHDBinarySHA256            string `json:"sshd_sha256"`
	OpenSSHBundleManifestSHA256 string `json:"openssh_bundle_manifest_sha256"`
	HostPublicKeySHA256         string `json:"host_public_key_sha256"`
	AuthorizedKeyCount          int    `json:"authorized_key_count"`
}

func runDoctorServer(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("doctor-server", stderr)
	manifestPath := onceStringFlag{name: "--config"}
	flags.Var(&manifestPath, "config", "path to a server-gateway .wt manifest")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if manifestPath.value == "" {
		return errors.New("doctor-server requires --config")
	}

	manifest, err := server.Load(manifestPath.value)
	if err != nil {
		return err
	}
	report, err := engine.PreflightServer(ctx, manifest)
	if err != nil {
		return err
	}
	selectedProfile, err := profile.Lookup(manifest.ProfileID)
	if err != nil {
		return err
	}
	return writeJSON(stdout, newServerDoctorOutput(
		report,
		selectedProfile.AuthenticationBindingStatus,
		selectedProfile.SupportStatus,
	))
}

func newServerDoctorOutput(
	report engine.ServerPreflightReport,
	authenticationBindingStatus profile.AuthenticationBindingStatus,
	supportStatus profile.SupportStatus,
) serverDoctorOutput {
	return serverDoctorOutput{
		Status:                      "preflight_ready",
		Role:                        "server",
		Profile:                     report.Profile,
		AuthenticationBindingStatus: string(authenticationBindingStatus),
		SupportStatus:               string(supportStatus),
		EngineVersion:               report.EngineVersion,
		OpenSSLVersion:              report.OpenSSLVersion,
		OpenSSLVersionText:          report.OpenSSLVersionText,
		OpenSSLLinkage:              report.OpenSSLLinkage,
		ExecutableFormat:            report.ExecutableFormat,
		StaticLibcryptoSHA256:       report.StaticLibcryptoSHA256,
		SSHDPath:                    report.SSHDPath,
		SSHDBinarySHA256:            report.SSHDBinarySHA256,
		OpenSSHBundleManifestSHA256: report.OpenSSHBundleManifestSHA256,
		HostPublicKeySHA256:         report.HostPublicKeySHA256,
		AuthorizedKeyCount:          report.AuthorizedKeyCount,
	}
}

func runTunnel(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) error {
	stderr = &synchronizedWriter{writer: stderr}
	if dependencies.loadProductionClientManifest == nil {
		return errors.New("production client manifest loader is required")
	}
	if dependencies.attestManagedClient == nil {
		return errors.New("managed client launch attestation dependency is required")
	}
	if dependencies.newServiceNotifier == nil {
		return errors.New("service notifier dependency is required")
	}
	flags := newFlagSet("run", stderr)
	manifestPath := onceStringFlag{name: "--config"}
	tunnelID := onceStringFlag{name: "--tunnel"}
	routeID := onceStringFlag{name: "--route"}
	once := onceBoolFlag{name: "--once"}
	readyFD := onceStringFlag{name: "--ready-fd"}
	managedLifecycle := onceBoolFlag{name: "--managed-lifecycle"}
	flags.Var(&manifestPath, "config", "path to a client-tunnels .wt manifest")
	flags.Var(&tunnelID, "tunnel", "ID of the tunnel to run")
	flags.Var(&routeID, "route", "reserved route ID using its active generation")
	flags.Var(&once, "once", "do not restart the tunnel after exit")
	flags.Var(&readyFD, "ready-fd", "internal inherited readiness pipe descriptor")
	flags.Var(&managedLifecycle, "managed-lifecycle", "internal launchd lifecycle ownership")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if err := authorizeManagedTunnelRun(dependencies); err != nil {
		return err
	}
	if routeID.value != "" {
		if manifestPath.value != "" || tunnelID.value != "" {
			return errors.New("run --route cannot be combined with --config or --tunnel")
		}
		resolved, resolveErr := resolveActiveRoute(routeID.value)
		if resolveErr != nil {
			return resolveErr
		}
		manifestPath.value = resolved.manifest
		tunnelID.value = routeID.value
	}
	if manifestPath.value == "" || tunnelID.value == "" {
		return errors.New("run requires --route or --config and --tunnel")
	}
	var readinessWriter *os.File
	if readyFD.value != "" {
		if !once.value {
			return errors.New("run --ready-fd requires --once")
		}
		fd, err := strconv.ParseUint(readyFD.value, 10, 32)
		if err != nil || fd != 3 {
			return errors.New("run --ready-fd must name inherited descriptor 3")
		}
		readinessWriter = os.NewFile(uintptr(fd), "warptweet-ready")
		info, err := readinessWriter.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			_ = readinessWriter.Close()
			return errors.New("run inherited readiness descriptor must be a pipe")
		}
		defer func() {
			if readinessWriter != nil {
				_ = readinessWriter.Close()
			}
		}()
	}

	manifest, err := dependencies.loadProductionClientManifest(manifestPath.value)
	if err != nil {
		return err
	}
	spec, err := clientSpec(manifest, tunnelID.value, manifestPath.value)
	if err != nil {
		return err
	}
	layout, err := productionClientLayout()
	if err != nil {
		return err
	}
	var lifecycleStore lifecycle.Store
	var lifecycleLock *os.File
	if managedLifecycle.value {
		lifecycleStore = lifecycle.Store{Root: layout.ClientRuntimeRoot}
		lifecycleLock, err = lifecycleStore.Lock(tunnelID.value)
		if err != nil {
			return err
		}
		defer lifecycle.Unlock(lifecycleLock)
		if err := lifecycleStore.Write(lifecycle.State{
			TunnelID: tunnelID.value, Phase: lifecycle.PhaseAwaitingReadiness,
			PID:            os.Getpid(),
			ListenEndpoint: fmt.Sprintf("%s:%d", spec.ListenAddress, spec.ListenPort),
			TargetHealth:   lifecycle.TargetHealthNotChecked,
		}); err != nil {
			return fmt.Errorf("write managed lifecycle start: %w", err)
		}
	}
	notifier, err := dependencies.newServiceNotifier()
	if err != nil {
		return fmt.Errorf("initialize service notifier: %w", err)
	}
	readyPublished := false
	defer func() {
		if readyPublished {
			if notifyErr := notifier.Stopping("WarpTweet tunnel stopping"); notifyErr != nil {
				fmt.Fprintf(stderr, "warptweet: notify service stopping: %v\n", notifyErr)
			}
		}
	}()

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	binary := engine.Binary{
		Path:   layout.SSHPath,
		SHA256: manifest.SSHBinarySHA256,
	}
	runtimeDirectory := filepath.Join(layout.ClientRuntimeRoot, tunnelID.value)
	provider := func(ctx context.Context) (supervisor.ReadyCommand, error) {
		launch, launchErr := dependencies.attestManagedClient(
			ctx,
			binary,
			runtimeDirectory,
			spec,
		)
		if launchErr != nil {
			return supervisor.ReadyCommand{}, launchErr
		}
		logger.Info(
			"WarpTweet tunnel preflight passed",
			"tunnel", tunnelID.value,
			"profile", launch.Preflight.Profile,
			"artifact_profile_id", launch.Preflight.ArtifactProfileID,
			"authentication_binding_status", string(spec.Profile.AuthenticationBindingStatus),
			"support_status", string(spec.Profile.SupportStatus),
			"engine_version", launch.Preflight.Version,
			"engine_sha256", launch.Preflight.SHA256,
			"openssl_version", launch.Preflight.OpenSSLVersion,
			"openssl_version_text", launch.Preflight.OpenSSLVersionText,
			"openssl_linkage", launch.Preflight.OpenSSLLinkage,
			"executable_format", launch.Preflight.ExecutableFormat,
			"elf_needed", launch.Preflight.DynamicLibraries,
			"host_key_alias", launch.Assets.HostKeyAlias,
			"host_key_pins", launch.Assets.HostKeyPins,
		)
		return supervisor.ReadyCommand{
			Command: supervisor.Command{
				Path:   launch.Path,
				Args:   launch.Args,
				Env:    launch.Env,
				Stdout: io.Discard,
				Stderr: stderr,
			},
			Readiness: launch.Readiness,
		}, nil
	}
	ready := func(_ context.Context, event supervisor.ReadyEvent) error {
		if err := notifier.Ready("WarpTweet authenticated transport and local listener ready"); err != nil {
			return err
		}
		readyPublished = true
		if managedLifecycle.value {
			if err := lifecycleStore.Write(lifecycle.State{
				TunnelID: tunnelID.value, Phase: lifecycle.PhaseReady,
				PID:            os.Getpid(),
				ListenEndpoint: fmt.Sprintf("%s:%d", spec.ListenAddress, spec.ListenPort),
				TargetHealth:   lifecycle.TargetHealthNotChecked,
			}); err != nil {
				return fmt.Errorf("write managed lifecycle readiness: %w", err)
			}
		}
		if readinessWriter != nil {
			if _, err := fmt.Fprintf(readinessWriter, "READY %d\n", event.PID); err != nil {
				return fmt.Errorf("publish inherited readiness: %w", err)
			}
			if err := readinessWriter.Close(); err != nil {
				return fmt.Errorf("close inherited readiness: %w", err)
			}
			readinessWriter = nil
		}
		logger.Info(
			"WarpTweet tunnel authenticated forward ready",
			"attempt", event.Attempt,
			"pid", event.PID,
			"target_health", "not_checked",
		)
		return nil
	}

	runErr := (supervisor.Supervisor{Logger: logger}).RunPreparedReady(ctx, provider, supervisor.Policy{
		Restart:        !once.value,
		InitialBackoff: manifest.Supervision.InitialBackoff.Value(),
		MaximumBackoff: manifest.Supervision.MaxBackoff.Value(),
	}, ready)
	if managedLifecycle.value {
		phase := lifecycle.PhaseFailed
		message := "tunnel controller exited"
		if runErr == nil || errors.Is(runErr, context.Canceled) {
			phase = lifecycle.PhaseStopped
			message = ""
		} else {
			message = runErr.Error()
		}
		if stateErr := lifecycleStore.Write(lifecycle.State{
			TunnelID: tunnelID.value, Phase: phase,
			ListenEndpoint: fmt.Sprintf("%s:%d", spec.ListenAddress, spec.ListenPort),
			TargetHealth:   lifecycle.TargetHealthNotChecked, Error: message,
		}); stateErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write managed lifecycle exit: %w", stateErr))
		}
	}
	return runErr
}

func parseClientSelection(name string, arguments []string, stderr io.Writer) (string, string, error) {
	flags := newFlagSet(name, stderr)
	manifestPath := onceStringFlag{name: "--config"}
	tunnelID := onceStringFlag{name: "--tunnel"}
	flags.Var(&manifestPath, "config", "path to a client-tunnels .wt manifest")
	flags.Var(&tunnelID, "tunnel", "ID of the tunnel to select")
	if err := parseFlags(flags, arguments); err != nil {
		return "", "", err
	}
	if manifestPath.value == "" || tunnelID.value == "" {
		return "", "", fmt.Errorf("%s requires --config and --tunnel", name)
	}
	return manifestPath.value, tunnelID.value, nil
}

func clientSpec(manifest config.Config, tunnelID, manifestPath string) (engine.ClientSpec, error) {
	var selectedTunnel *config.Tunnel
	for index := range manifest.Tunnels {
		if manifest.Tunnels[index].ID == tunnelID {
			selectedTunnel = &manifest.Tunnels[index]
			break
		}
	}
	if selectedTunnel == nil {
		return engine.ClientSpec{}, fmt.Errorf("manifest contains no tunnel with ID %q", tunnelID)
	}
	selectedProfile, err := profile.Lookup(manifest.ProfileID)
	if err != nil {
		return engine.ClientSpec{}, err
	}
	layout, err := productionClientLayout()
	if err != nil {
		return engine.ClientSpec{}, err
	}
	identityFile := layout.ClientIdentityPath
	knownHostsFile := layout.ClientKnownHostsPath
	emptyTrust := layout.ClientGlobalKnownHostsPath
	if store, storeErr := productionRouteStore(); storeErr == nil {
		if activeManifest, manifestErr := store.ManifestPath(selectedTunnel.ID); manifestErr == nil {
			if identity, idErr := store.IdentityPath(selectedTunnel.ID); idErr == nil {
				generationDir := filepath.Dir(activeManifest)
				identityFile = identity
				knownHostsFile = filepath.Join(generationDir, "known_hosts")
				emptyTrust = filepath.Join(generationDir, "known_hosts.empty")
			}
		}
	}
	return engine.ClientSpec{
		TunnelID:             selectedTunnel.ID,
		ServerAddress:        canonicalAddress(manifest.Server.Address),
		ServerPort:           uint16(manifest.Server.Port),
		ServerUser:           manifest.Server.User,
		ListenAddress:        canonicalAddress(selectedTunnel.Listen.Address),
		ListenPort:           uint16(selectedTunnel.Listen.Port),
		TargetAddress:        canonicalAddress(selectedTunnel.Target.Address),
		TargetPort:           uint16(selectedTunnel.Target.Port),
		IdentityFile:         identityFile,
		KnownHostsFile:       knownHostsFile,
		GlobalKnownHostsFile: emptyTrust,
		Profile:              selectedProfile,
	}, nil
}

type resolvedRoute struct {
	manifest string
}

func resolveActiveRoute(routeID string) (resolvedRoute, error) {
	store, err := productionRouteStore()
	if err != nil {
		return resolvedRoute{}, err
	}
	manifest, err := store.ManifestPath(routeID)
	if err != nil {
		return resolvedRoute{}, err
	}
	return resolvedRoute{manifest: manifest}, nil
}

func productionClientManifest(path, productionPath string) bool {
	if path == "" || productionPath == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = filepath.Clean(path)
	}
	want, err := filepath.EvalSymlinks(productionPath)
	if err != nil {
		want = filepath.Clean(productionPath)
	}
	return filepath.Clean(resolved) == filepath.Clean(want)
}

func productionClientLayout() (artifactprofile.Layout, error) {
	selected, err := artifactprofile.Current()
	if err != nil {
		return artifactprofile.Layout{}, err
	}
	if selected.Layout.SSHPath == "" ||
		selected.Layout.ClientManifestPath == "" ||
		selected.Layout.ClientIdentityPath == "" ||
		selected.Layout.ClientKnownHostsPath == "" ||
		selected.Layout.ClientGlobalKnownHostsPath == "" ||
		selected.Layout.ClientRuntimeRoot == "" {
		return artifactprofile.Layout{}, fmt.Errorf(
			"artifact profile %q does not define a complete client layout",
			selected.ID,
		)
	}
	return selected.Layout, nil
}

func canonicalAddress(address netip.Addr) netip.Addr {
	return address.Unmap()
}

func detectManifestKind(path string) (string, error) {
	if filepath.Ext(path) != config.ManifestExtension {
		return "", fmt.Errorf("manifest path %q must use the %q extension", path, config.ManifestExtension)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open manifest %q: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, manifestSize+1))
	if err != nil {
		return "", fmt.Errorf("read manifest kind: %w", err)
	}
	if len(data) > manifestSize {
		return "", fmt.Errorf("manifest exceeds %d bytes", manifestSize)
	}
	var header struct {
		Kind string `json:"kind"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&header); err != nil {
		return "", fmt.Errorf("decode manifest kind: %w", err)
	}
	if strings.TrimSpace(header.Kind) == "" {
		return "", errors.New("manifest kind is required")
	}
	return header.Kind, nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parseFlags(flags *flag.FlagSet, arguments []string) error {
	args, err := parseFlagsAllowArgs(flags, arguments)
	if err != nil {
		return err
	}
	if len(args) != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(args, " "))
	}
	return nil
}

func parseFlagsAllowArgs(flags *flag.FlagSet, arguments []string) ([]string, error) {
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, outcome.Help()
		}
		return nil, outcome.Usage(err.Error())
	}
	return flags.Args(), nil
}

type onceStringFlag struct {
	name  string
	value string
	set   bool
}

type onceBoolFlag struct {
	name  string
	value bool
	set   bool
}

func (flagValue *onceBoolFlag) String() string {
	return strconv.FormatBool(flagValue.value)
}

func (flagValue *onceBoolFlag) Set(value string) error {
	if flagValue.set {
		return fmt.Errorf("%s may be specified only once", flagValue.name)
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("parse %s: %w", flagValue.name, err)
	}
	flagValue.value = parsed
	flagValue.set = true
	return nil
}

func (*onceBoolFlag) IsBoolFlag() bool {
	return true
}

func (flagValue *onceStringFlag) String() string {
	return flagValue.value
}

func (flagValue *onceStringFlag) Set(value string) error {
	if flagValue.set {
		return fmt.Errorf("%s may be specified only once", flagValue.name)
	}
	flagValue.value = value
	flagValue.set = true
	return nil
}

func readPublicKeyFile(path string) ([]byte, error) {
	return readBoundedRegularFile(path, "client public key", server.MaxAuthorizedKeyInputBytes)
}

func readHostPublicKeyFile(path string) ([]byte, error) {
	return readBoundedRegularFile(path, "host public key", knownhosts.MaxPublicKeyLineBytes)
}

func readBoundedRegularFile(path, description string, maximumBytes int) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s %q: %w", description, path, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s %q must not be a symbolic link", description, path)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %q must be a regular file", description, path)
	}
	if pathInfo.Size() > int64(maximumBytes) {
		return nil, fmt.Errorf("%s %q exceeds %d bytes", description, path, maximumBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s %q: %w", description, path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened %s %q: %w", description, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %q must be a regular file", description, path)
	}
	if !os.SameFile(pathInfo, info) {
		return nil, fmt.Errorf("%s %q changed while it was opened", description, path)
	}
	if info.Size() > int64(maximumBytes) {
		return nil, fmt.Errorf("%s %q exceeds %d bytes", description, path, maximumBytes)
	}

	contents, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", description, path, err)
	}
	if len(contents) > maximumBytes {
		return nil, fmt.Errorf("%s %q exceeds %d bytes", description, path, maximumBytes)
	}
	return contents, nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

type publicCommand struct {
	Name  string
	Usage string
}

var publicCommands = []publicCommand{
	{Name: "host", Usage: "warptweet host --to <port|ip:port> [--name <label>] [--access-for 30d] [--out path] [--stdout] [--listen ip:port] [--no-invite] [--json]"},
	{Name: "connect", Usage: "warptweet connect <invite.wtinvite> [--yes] [--listen-port <port>] [--restart unless-stopped|manual] [--proof <proof.json>]"},
	{Name: "profile", Usage: "warptweet profile"},
	{Name: "validate", Usage: "warptweet validate --config <manifest.wt>"},
	{Name: "render-client", Usage: "warptweet render-client --config <client.wt> --tunnel <id>"},
	{Name: "render-server", Usage: "warptweet render-server --config <server.wt>"},
	{Name: "render-authorized-key", Usage: "warptweet render-authorized-key --config <server.wt> --public-key <client.pub> --not-after <rfc3339>"},
	{Name: "render-known-host", Usage: "warptweet render-known-host --config <client.wt> --tunnel <id> --public-key <host.pub>"},
	{Name: "doctor", Usage: "warptweet doctor --config <client.wt> --tunnel <id>"},
	{Name: "doctor-server", Usage: "warptweet doctor-server --config <server.wt>"},
	{Name: "enroll", Usage: "warptweet enroll <invite.wtinvite> [--yes] [--prepare-only] [--proof <proof.json>]"},
	{Name: "routes", Usage: "warptweet routes [--json]"},
	{Name: "up", Usage: "warptweet up <route-id>"},
	{Name: "repair", Usage: "warptweet repair <route-id>"},
	{Name: "status", Usage: "warptweet status [<route-id>] [--json]"},
	{Name: "down", Usage: "warptweet down <route-id>"},
	{Name: "reconcile", Usage: "warptweet reconcile"},
	{Name: "rotate", Usage: "warptweet rotate <tunnel-id>"},
	{Name: "revoke", Usage: "warptweet revoke <tunnel-id>"},
	{Name: "uninstall", Usage: "warptweet uninstall --preserve-identity"},
	{Name: "version", Usage: "warptweet version"},
}

func writeUsage(writer io.Writer) {
	_, _ = io.WriteString(writer, "WarpTweet: open-source fail-closed post-quantum TCP tunneling\n\nUsage:\n")
	for _, command := range publicCommands {
		_, _ = io.WriteString(writer, "  "+command.Usage+"\n")
	}
}
