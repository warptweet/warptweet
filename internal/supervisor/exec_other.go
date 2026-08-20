//go:build !linux

package supervisor

import (
	"context"
	"errors"
	"os/exec"
)

func (ExecLauncher) Start(ctx context.Context, command Command) (Process, error) {
	if ctx == nil {
		return nil, errors.New("supervised command context is required")
	}
	if command.Path == "" {
		return nil, errors.New("supervised command path is required")
	}
	if command.Env == nil {
		return nil, errors.New("supervised command environment is required")
	}
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	process.Env = append([]string(nil), command.Env...)
	process.Stdin = nil
	process.Stdout = command.Stdout
	process.Stderr = command.Stderr
	if err := process.Start(); err != nil {
		return nil, err
	}
	return &execProcess{command: process}, nil
}
