package engine

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type clientCommandOutput struct {
	stdout []byte
	stderr []byte
}

type clientCommandRunner interface {
	Run(context.Context, string, []string, ...string) (clientCommandOutput, error)
}

type execClientCommandRunner struct{}

func (execClientCommandRunner) Run(
	ctx context.Context,
	path string,
	environment []string,
	arguments ...string,
) (clientCommandOutput, error) {
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = append([]string(nil), environment...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := clientCommandOutput{
		stdout: append([]byte(nil), stdout.Bytes()...),
		stderr: append([]byte(nil), stderr.Bytes()...),
	}
	if err == nil {
		return result, nil
	}
	message := strings.TrimSpace(string(append(append([]byte(nil), result.stderr...), result.stdout...)))
	if message == "" {
		return result, err
	}
	return result, fmt.Errorf("%w: %s", err, message)
}

// sanitizedClientEnvironment deliberately ignores the ambient environment.
// The OpenSSH client and preflight commands use exact executable paths and do
// not require PATH lookup. A fixed C locale keeps diagnostic and configuration
// output deterministic without admitting loader, allocator, locale-path, or
// OpenSSL process overrides.
func sanitizedClientEnvironment(_ []string) []string {
	return []string{"LANG=C", "LC_ALL=C"}
}
