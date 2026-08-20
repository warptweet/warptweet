//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func (ExecLauncher) Start(ctx context.Context, command Command) (Process, error) {
	if ctx == nil {
		return nil, fmt.Errorf("supervised command context is required")
	}
	if command.Path == "" {
		return nil, fmt.Errorf("supervised command path is required")
	}
	if command.Env == nil {
		return nil, fmt.Errorf("supervised command environment is required")
	}
	executable, err := os.Open(command.Path)
	if err != nil {
		return nil, fmt.Errorf("open attested executable: %w", err)
	}
	process := exec.CommandContext(ctx, "/proc/self/fd/"+strconv.Itoa(3), command.Args...)
	process.Env = append([]string(nil), command.Env...)
	process.Stdin = nil
	process.Stdout = command.Stdout
	process.Stderr = command.Stderr
	process.ExtraFiles = []*os.File{executable}
	if err := process.Start(); err != nil {
		_ = executable.Close()
		return nil, err
	}
	_ = executable.Close()
	return &execProcess{command: process}, nil
}
