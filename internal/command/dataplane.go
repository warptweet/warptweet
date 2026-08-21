package command

import (
	"context"
	"io"

	"warptweet.com/warptweet/internal/dataplane"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/server"
)

func runServerDataPlane(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server data-plane", stderr)
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
	return dataplane.Serve(ctx, policy, stdout)
}
