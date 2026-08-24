package command

import (
	"context"
	"fmt"
	"net/netip"

	"warptweet.com/warptweet/internal/config"
	"warptweet.com/warptweet/internal/locator"
)

func resolveManifestServer(
	ctx context.Context,
	manifest config.Config,
	options locator.ResolveOptions,
	connect bool,
) (locator.ResolvedDialPlan, netip.Addr, error) {
	host, err := locator.ParseDialHost(manifest.Server.Host)
	if err != nil {
		return locator.ResolvedDialPlan{}, netip.Addr{}, fmt.Errorf("server.host: %w", err)
	}
	if host.IP.IsValid() && host.IP.IsLoopback() {
		options.AllowLoopback = true
	}
	plan, err := locator.Resolve(ctx, host, options)
	if err != nil {
		return locator.ResolvedDialPlan{}, netip.Addr{}, err
	}
	if len(plan.Candidates) == 0 {
		return plan, netip.Addr{}, fmt.Errorf("server.host: no candidates")
	}
	if !connect || len(plan.Candidates) == 1 {
		return plan, plan.Candidates[0], nil
	}
	selected, err := locator.Select(ctx, plan, uint16(manifest.Server.Port), options)
	if err != nil {
		return plan, netip.Addr{}, err
	}
	return plan, selected, nil
}
