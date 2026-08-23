package command

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"warptweet.com/warptweet/internal/hostsign"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/server"
	"warptweet.com/warptweet/internal/systemdnotify"
)

func runServerHostSign(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server host-sign", stderr)
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/run/warptweet/hostsign", 0o750); err != nil {
		return err
	}
	if err := os.Chown("/run/warptweet/hostsign", 0, installlayout.LinuxPrivsepGID); err != nil {
		return err
	}
	_ = os.Remove(installlayout.HostSignSocket)
	listener, err := net.Listen("unix", installlayout.HostSignSocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(installlayout.HostSignSocket, 0o660); err != nil {
		_ = listener.Close()
		return err
	}
	if err := os.Chown(installlayout.HostSignSocket, 0, installlayout.LinuxPrivsepGID); err != nil {
		_ = listener.Close()
		return err
	}
	notifier, err := systemdnotify.FromEnvironment(os.Getenv)
	if err != nil {
		_ = listener.Close()
		return err
	}
	if err := notifier.Ready("host sign socket ready"); err != nil {
		_ = listener.Close()
		return err
	}
	if stdout != nil {
		_, _ = fmt.Fprintf(stdout, "host sign listening\n")
	}
	return hostsign.Serve(ctx, listener, manifest.HostKeyPath, installlayout.LinuxPrivsepUID)
}
