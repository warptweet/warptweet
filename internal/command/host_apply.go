package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/inspectnet"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const (
	hostStepCertWrite         = "cert-write"
	hostStepManifestWrite     = "manifest-write"
	hostStepDataPlaneRestart  = "data-plane-restart"
	hostStepEnrollmentRestart = "enrollment-restart"
	hostStepReadinessVerify   = "readiness-verify"
	hostStepInviteRecord      = "invite-record-create"
)

var errHostInterrupted = errors.New("host apply interrupted")

type hostApplyEnv struct {
	ManifestPath   string
	StateDir       string
	InviteDir      string
	ClientsDir     string
	CertPath       string
	KeyPath        string
	InterruptAfter string
	Now            time.Time

	Discover   func() (netip.Addr, error)
	Interfaces func() ([]inspectnet.Interface, error)

	ApplyDataPlane  func(restart bool, endpoint netip.AddrPort) (string, error)
	ApplyEnrollment func(restart bool, endpoint netip.AddrPort, pin string) (string, error)
	ProbeTCP        func(endpoint netip.AddrPort) bool

	EnsureIdentity   func(ctx context.Context) (publicKey string, created bool, err error)
	EnsureTLS        func(addrs []net.IP, now time.Time) (pin string, created, renewed bool, err error)
	WriteSSHD        func(manifest server.Config) error
	AllowTestDigests bool
}

type hostApplyInput struct {
	Target               netip.AddrPort
	Flags                hostPublicationFlags
	NoInvite             bool
	Label                string
	AuthorizationSeconds int64
}

type hostApplyResult struct {
	Manifest                     server.Config
	Publication                  hostPublication
	HostPublicKey                string
	CreatedHostKey               bool
	EnrollmentPin                string
	CreatedEnrollmentIdentity    bool
	RenewedEnrollmentCertificate bool
	DataPlaneStatus              string
	EnrollStatus                 string
	Invite                       enrollment.Invite
	InviteBlob                   []byte
	ResumedInvite                bool
	Desired                      hostRevision
}

func productionHostApplyEnv() hostApplyEnv {
	return hostApplyEnv{
		ManifestPath: installlayout.ServerManifestPath,
		StateDir:     serverStateDirectory,
		InviteDir:    inviteDirectory,
		ClientsDir:   installlayout.ClientsDirectory,
		CertPath:     installlayout.ServerEnrollmentTLSCertPath,
		KeyPath:      installlayout.ServerEnrollmentTLSKeyPath,
		Discover:     discoverHostBind,
		Interfaces:   inspectnet.ListHostInterfaces,
		ProbeTCP:     probeTCPListener,
		EnsureIdentity: func(ctx context.Context) (string, bool, error) {
			return ensureHostIdentity(ctx)
		},
		EnsureTLS: func(addrs []net.IP, now time.Time) (string, bool, bool, error) {
			return enrollment.EnsureTLSIdentity(
				installlayout.ServerEnrollmentTLSCertPath,
				installlayout.ServerEnrollmentTLSKeyPath,
				addrs,
				now,
			)
		},
		WriteSSHD: writeHostSSHDFiles,
		ApplyDataPlane: func(restart bool, endpoint netip.AddrPort) (string, error) {
			return ensureSSHDStarted(context.Background(), endpoint, restart)
		},
		ApplyEnrollment: func(restart bool, endpoint netip.AddrPort, pin string) (string, error) {
			started, err := ensureEnrollListenStarted(endpoint, pin, restart)
			if err != nil {
				return "", err
			}
			if started {
				return "started", nil
			}
			return "already_running", nil
		},
	}
}

func writeHostSSHDFiles(manifest server.Config) error {
	if _, err := os.Lstat(manifest.AuthorizedKeysPath); os.IsNotExist(err) {
		if err := os.WriteFile(manifest.AuthorizedKeysPath, nil, 0o644); err != nil {
			return err
		}
	}
	rendered, err := server.Render(manifest)
	if err != nil {
		return err
	}
	return writeFileAtomic(installlayout.ServerConfigPath, rendered, 0o644)
}

func (env hostApplyEnv) checkpoint(step string) error {
	if env.InterruptAfter != "" && env.InterruptAfter == step {
		return fmt.Errorf("%w: after %s", errHostInterrupted, step)
	}
	return nil
}

func applyHostConfiguration(ctx context.Context, env hostApplyEnv, input hostApplyInput) (hostApplyResult, error) {
	if env.Now.IsZero() {
		env.Now = time.Now().UTC()
	}
	if env.Discover == nil {
		env.Discover = discoverHostBind
	}
	if env.ProbeTCP == nil {
		env.ProbeTCP = probeTCPListener
	}
	stored, err := loadManifestAt(env.ManifestPath)
	if err != nil {
		return hostApplyResult{}, err
	}
	ifaces := []inspectnet.Interface{}
	if input.Flags.ListenInterface.set {
		if env.Interfaces == nil {
			return hostApplyResult{}, errors.New("listen-interface resolver is required")
		}
		ifaces, err = env.Interfaces()
		if err != nil {
			return hostApplyResult{}, err
		}
	}
	publication, err := resolveHostPublication(input.Flags, stored, env.Discover, ifaces)
	if err != nil {
		return hostApplyResult{}, err
	}
	if env.EnsureIdentity == nil {
		return hostApplyResult{}, errors.New("host identity helper is required")
	}
	hostPublicKey, createdHostKey, err := env.EnsureIdentity(ctx)
	if err != nil {
		return hostApplyResult{}, err
	}
	if env.EnsureTLS == nil {
		return hostApplyResult{}, errors.New("enrollment TLS helper is required")
	}
	pin, createdTLS, renewedTLS, err := env.EnsureTLS(
		[]net.IP{net.IP(publication.DataListen.Address.AsSlice())},
		env.Now,
	)
	if err != nil {
		return hostApplyResult{}, fmt.Errorf("ensure enrollment TLS identity: %w", err)
	}
	if err := env.checkpoint(hostStepCertWrite); err != nil {
		return hostApplyResult{}, err
	}
	if err := refuseHostTargetChangeAt(env.ManifestPath, env.ClientsDir, env.InviteDir, input.Target); err != nil {
		return hostApplyResult{}, err
	}
	var storedNetwork *server.Network
	if stored != nil {
		storedNetwork = &stored.Network
	}
	network, publishedChanged, err := server.ProposeNetwork(
		publication.DataListen,
		publication.EnrollListen,
		publication.DataDial,
		publication.EnrollDial,
		storedNetwork,
	)
	if err != nil {
		return hostApplyResult{}, err
	}
	if publishedChanged {
		if err := refusePublishedLocatorChangeAt(env.ClientsDir, env.InviteDir); err != nil {
			return hostApplyResult{}, err
		}
	}
	manifest, err := writeHostManifestNetwork(env, input.Target, network)
	if err != nil {
		return hostApplyResult{}, err
	}
	desired, err := computeHostRevision(hostDesiredKind, manifest.Network, env.CertPath)
	if err != nil {
		return hostApplyResult{}, err
	}
	if err := writeHostRevision(desiredRevisionPath(env.StateDir), desired); err != nil {
		return hostApplyResult{}, err
	}
	if err := env.checkpoint(hostStepManifestWrite); err != nil {
		return hostApplyResult{}, err
	}

	applied, appliedOK, err := loadHostRevision(appliedReceiptPath(env.StateDir))
	if err != nil {
		return hostApplyResult{}, err
	}
	appliedMismatch := !appliedOK || !desired.equal(applied)
	dataListenChanged := stored == nil || stored.Network.Data.Listen.AddrPort() != publication.DataListen.AddrPort()
	enrollListenChanged := stored == nil || stored.Network.Enrollment.Listen.AddrPort() != publication.EnrollListen.AddrPort()
	certChanged := !appliedOK || applied.CertLeafSHA256 != desired.CertLeafSHA256
	targetChanged := stored != nil && netip.AddrPortFrom(stored.Target.Address, uint16(stored.Target.Port)) != input.Target
	restartData := dataListenChanged || appliedMismatch || targetChanged
	restartEnroll := publishedChanged || enrollListenChanged || certChanged || appliedMismatch

	if env.ApplyDataPlane == nil {
		return hostApplyResult{}, errors.New("data-plane apply helper is required")
	}
	dataStatus, err := env.ApplyDataPlane(restartData, publication.DataListen.AddrPort())
	if err != nil {
		return hostApplyResult{}, fmt.Errorf("start WarpTweet data plane: %w", err)
	}
	if err := env.checkpoint(hostStepDataPlaneRestart); err != nil {
		return hostApplyResult{}, err
	}
	if env.ApplyEnrollment == nil {
		return hostApplyResult{}, errors.New("enrollment apply helper is required")
	}
	enrollStatus, err := env.ApplyEnrollment(restartEnroll, publication.EnrollListen.AddrPort(), pin)
	if err != nil {
		return hostApplyResult{}, fmt.Errorf("start enrollment listener: %w", err)
	}
	if err := env.checkpoint(hostStepEnrollmentRestart); err != nil {
		return hostApplyResult{}, err
	}
	if !env.ProbeTCP(publication.DataListen.AddrPort()) {
		return hostApplyResult{}, fmt.Errorf("data listen %s did not accept", publication.DataListen.AddrPort())
	}
	if !env.ProbeTCP(publication.EnrollListen.AddrPort()) {
		return hostApplyResult{}, fmt.Errorf("enrollment listen %s did not accept", publication.EnrollListen.AddrPort())
	}
	if err := writeHostRevision(appliedReceiptPath(env.StateDir), hostRevision{
		Kind:           hostAppliedKind,
		SchemaVersion:  hostRevisionVer,
		NetworkSHA256:  desired.NetworkSHA256,
		CertLeafSHA256: desired.CertLeafSHA256,
	}); err != nil {
		return hostApplyResult{}, err
	}
	if err := env.checkpoint(hostStepReadinessVerify); err != nil {
		return hostApplyResult{}, err
	}

	result := hostApplyResult{
		Manifest:                     manifest,
		Publication:                  publication,
		HostPublicKey:                hostPublicKey,
		CreatedHostKey:               createdHostKey,
		EnrollmentPin:                pin,
		CreatedEnrollmentIdentity:    createdTLS,
		RenewedEnrollmentCertificate: renewedTLS,
		DataPlaneStatus:              dataStatus,
		EnrollStatus:                 enrollStatus,
		Desired:                      desired,
	}
	if input.NoInvite {
		return result, nil
	}
	invite, blob, resumed, err := resumeOrMintInvite(ctx, env, input, manifest, hostPublicKey, pin)
	if err != nil {
		return hostApplyResult{}, err
	}
	if err := env.checkpoint(hostStepInviteRecord); err != nil {
		return hostApplyResult{}, err
	}
	result.Invite = invite
	result.InviteBlob = blob
	result.ResumedInvite = resumed
	return result, nil
}

func resumeOrMintInvite(
	ctx context.Context,
	env hostApplyEnv,
	input hostApplyInput,
	manifest server.Config,
	hostPublicKey, pin string,
) (enrollment.Invite, []byte, bool, error) {
	issued, err := enrollment.UnusedIssuedForGeneration(env.InviteDir, manifest.Network.PublishedEndpointGeneration, env.Now)
	if err != nil {
		return enrollment.Invite{}, nil, false, err
	}
	if len(issued) > 1 {
		return enrollment.Invite{}, nil, false, fmt.Errorf("multiple unused issued invites exist for published_endpoint_generation %d", manifest.Network.PublishedEndpointGeneration)
	}
	if len(issued) == 1 {
		blob, err := enrollment.LoadIssuedBlob(env.InviteDir, issued[0].InviteID)
		if err != nil {
			return enrollment.Invite{}, nil, false, err
		}
		return issued[0].Invite, append(append([]byte(nil), blob...), '\n'), true, nil
	}
	invite, record, err := mintServerInvite(ctx, input.Label, input.Target, manifest, hostPublicKey, pin, input.AuthorizationSeconds, env.Now)
	if err != nil {
		return enrollment.Invite{}, nil, false, err
	}
	if err := enrollment.Store(env.InviteDir, record); err != nil {
		return enrollment.Invite{}, nil, false, err
	}
	blob, err := enrollment.LoadIssuedBlob(env.InviteDir, invite.InviteID)
	if err != nil {
		return enrollment.Invite{}, nil, false, err
	}
	return invite, append(append([]byte(nil), blob...), '\n'), false, nil
}

func loadManifestAt(path string) (*server.Config, error) {
	_, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	manifest, err := server.Load(path)
	if err != nil {
		return nil, err
	}
	return &manifest, nil
}

func writeHostManifestNetwork(env hostApplyEnv, targetEndpoint netip.AddrPort, network server.Network) (server.Config, error) {
	sshdDigest, err := fileSHA256(installlayout.SSHDPath)
	if err != nil {
		if existing, loadErr := loadManifestAt(env.ManifestPath); loadErr == nil && existing != nil &&
			existing.SSHDBinarySHA256 != "" && existing.SSHDBinarySHA256 != stringsRepeatZero() {
			sshdDigest = existing.SSHDBinarySHA256
		} else if env.AllowTestDigests {
			sshdDigest = sha256OfString(env.ManifestPath + ":sshd")
		} else {
			return server.Config{}, fmt.Errorf("hash sshd binary: %w", err)
		}
	}
	bundleDigest, err := fileSHA256(installlayout.OpenSSHBundleManifestPath)
	if err != nil {
		if existing, loadErr := loadManifestAt(env.ManifestPath); loadErr == nil && existing != nil &&
			existing.OpenSSHBundleManifestSHA256 != "" && existing.OpenSSHBundleManifestSHA256 != stringsRepeatZero() {
			bundleDigest = existing.OpenSSHBundleManifestSHA256
		} else if env.AllowTestDigests {
			bundleDigest = sha256OfString(env.ManifestPath + ":bundle")
		} else {
			return server.Config{}, fmt.Errorf("hash OpenSSH bundle manifest: %w", err)
		}
	}
	manifest := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            sshdDigest,
		OpenSSHBundleManifestSHA256: bundleDigest,
		Network:                     network,
		Target: server.Endpoint{
			Address: targetEndpoint.Addr(),
			Port:    server.Port(targetEndpoint.Port()),
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: installlayout.AuthorizedKeysDirectory + "/" + server.DefaultDedicatedUser,
	}
	if stored, loadErr := loadManifestAt(env.ManifestPath); loadErr == nil && stored != nil {
		if stored.ProfileID != "" {
			manifest.ProfileID = stored.ProfileID
		}
		if stored.HostKeyPath != "" {
			manifest.HostKeyPath = stored.HostKeyPath
		}
		if stored.AuthorizedKeysPath != "" {
			manifest.AuthorizedKeysPath = stored.AuthorizedKeysPath
		}
		if stored.DedicatedUser != "" {
			manifest.DedicatedUser = stored.DedicatedUser
		}
	}
	if err := server.Validate(manifest); err != nil {
		return server.Config{}, err
	}
	if err := writeServerManifestAtomic(env.ManifestPath, manifest); err != nil {
		return server.Config{}, err
	}
	if env.WriteSSHD != nil {
		if err := env.WriteSSHD(manifest); err != nil {
			return server.Config{}, err
		}
	}
	return manifest, nil
}

func stringsRepeatZero() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

func sha256OfString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func refuseHostTargetChangeAt(manifestPath, clientsDir, inviteDir string, targetEndpoint netip.AddrPort) error {
	existing, err := loadManifestAt(manifestPath)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	current := netip.AddrPortFrom(existing.Target.Address, uint16(existing.Target.Port))
	if current == targetEndpoint {
		return nil
	}
	clients, err := enrollment.ListClients(clientsDir)
	if err != nil {
		return fmt.Errorf("list grants before target change: %w", err)
	}
	invites, err := enrollment.List(inviteDir)
	if err != nil {
		return fmt.Errorf("list invites before target change: %w", err)
	}
	for _, record := range clients {
		if record.Status != enrollment.ClientStatusExpired && record.Status != enrollment.ClientStatusRevoked {
			return fmt.Errorf("host target cannot change from %s to %s while grant %s is %s", current, targetEndpoint, record.ClientID, record.Status)
		}
	}
	for _, record := range invites {
		if record.Status == enrollment.StatusIssued {
			return fmt.Errorf("host target cannot change from %s to %s while invite %s is issued", current, targetEndpoint, record.InviteID)
		}
	}
	return nil
}

func refusePublishedLocatorChangeAt(clientsDir, inviteDir string) error {
	clients, err := enrollment.ListClients(clientsDir)
	if err != nil {
		return fmt.Errorf("list grants before published endpoint change: %w", err)
	}
	invites, err := enrollment.List(inviteDir)
	if err != nil {
		return fmt.Errorf("list invites before published endpoint change: %w", err)
	}
	return publicationChangeBlocked(clients, invites)
}

func withHostOperationLock(fn func() error) error {
	return enrollment.WithExclusiveLock(serverStateDirectory, hostStateLockName, fn)
}

func withHostOperationLockAt(directory string, fn func() error) error {
	return enrollment.WithExclusiveLock(directory, hostStateLockName, fn)
}
