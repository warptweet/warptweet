package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"warptweet.com/warptweet/internal/command"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(command.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
