package command

import (
	"context"
	"io"

	"warptweet.com/warptweet/internal/dataplane"
	"warptweet.com/warptweet/internal/grantsession"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/server"
)

func runServerDataPlane(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server data-plane", stderr)
	preflightOnly := onceBoolFlag{name: "--preflight-only"}
	allowHostKey := onceBoolFlag{name: "--allow-host-key"}
	flags.Var(&preflightOnly, "preflight-only", "verify installed identity and exit")
	flags.Var(&allowHostKey, "allow-host-key", "load the host private key in-process instead of the signer socket")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	policy, err := dataplane.NewPolicy(manifest)
	if err != nil {
		return err
	}
	policy.Grant = &grantsession.Authority{
		Root:        installlayout.GrantSessionsDirectory,
		Clients:     installlayout.ClientsDirectory,
		LockPath:    installlayout.GrantAuthorityLockPath,
		ExpectedExe: installlayout.ControllerPath,
	}
	policy.ControlSocket = installlayout.DataPlaneControlSocket
	if !allowHostKey.value {
		policy.HostSignSocket = installlayout.HostSignSocket
	}
	if err := dataplane.Preflight(policy); err != nil {
		return err
	}
	if preflightOnly.value {
		return nil
	}
	return dataplane.Serve(ctx, policy, stdout)
}
