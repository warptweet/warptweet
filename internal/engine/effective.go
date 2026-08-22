package engine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"warptweet.com/warptweet/internal/enrollment"
)

// ValidateEffectiveClientConfig asks the pinned OpenSSH engine to resolve the
// closed command-line policy, then verifies its security-critical effective
// values. This catches parser, option-name, and packaging drift before connect.
func ValidateEffectiveClientConfig(ctx context.Context, binaryPath string, spec ClientSpec) error {
	policy, err := newClientPolicy(spec, "")
	if err != nil {
		return err
	}
	return validateEffectiveClientConfigWithEnvironment(
		ctx,
		binaryPath,
		clientPolicyArguments(policy),
		policy,
		sanitizedClientEnvironment(os.Environ()),
	)
}

// ValidateManagedEffectiveClientConfig resolves and checks the exact
// foreground ControlMaster policy used for authenticated-forward readiness.
// runtimeDirectory must be the fixed directory derived from spec.TunnelID.
func ValidateManagedEffectiveClientConfig(
	ctx context.Context,
	binaryPath string,
	runtimeDirectory string,
	spec ClientSpec,
) error {
	policy, err := managedClientPolicy(runtimeDirectory, spec)
	if err != nil {
		return err
	}
	return validateEffectiveClientConfigWithEnvironment(
		ctx,
		binaryPath,
		clientPolicyArguments(policy),
		policy,
		sanitizedClientEnvironment(os.Environ()),
	)
}

func validateEffectiveClientConfigWithEnvironment(
	ctx context.Context,
	binaryPath string,
	arguments []string,
	policy clientPolicy,
	environment []string,
) error {
	output, err := effectiveConfigOutput(ctx, binaryPath, arguments, environment)
	if err != nil {
		return fmt.Errorf("resolve effective OpenSSH client configuration: %w", err)
	}
	options, err := parseEffectiveOptions(output)
	if err != nil {
		return err
	}

	expected := make(map[string][]string)
	for _, option := range policy.options {
		if !option.expectEffective {
			continue
		}
		key := strings.ToLower(option.name)
		expected[key] = append(expected[key], option.effectiveValues...)
	}
	for key, values := range expected {
		actual := options[key]
		if len(actual) != len(values) {
			return fmt.Errorf("effective OpenSSH option %s has %d values, want %d", key, len(actual), len(values))
		}
		for index := range values {
			if actual[index] != values[index] {
				return fmt.Errorf("effective OpenSSH option %s is %q, want %q", key, actual[index], values[index])
			}
		}
	}
	if values, present := options["gssapiauthentication"]; present {
		if len(values) != 1 || values[0] != "no" {
			return fmt.Errorf(
				"effective OpenSSH option gssapiauthentication is %q, want no or compiled-out",
				values,
			)
		}
	}
	for _, forbidden := range []string{
		"proxycommand",
		"proxyjump",
		"knownhostscommand",
		"localcommand",
		"remotecommand",
		"remoteforward",
		"dynamicforward",
	} {
		if values, present := options[forbidden]; present {
			return fmt.Errorf("effective OpenSSH option %s must be absent, got %q", forbidden, values)
		}
	}
	return nil
}

func effectiveConfigOutput(
	ctx context.Context,
	binaryPath string,
	arguments []string,
	environment []string,
) ([]byte, error) {
	queryArguments := make([]string, 0, len(arguments)+1)
	queryArguments = append(queryArguments, "-G")
	queryArguments = append(queryArguments, arguments...)
	command := exec.CommandContext(ctx, binaryPath, queryArguments...)
	command.Env = append([]string(nil), environment...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", err, message)
	}
	if diagnostics := strings.TrimSpace(stderr.String()); diagnostics != "" {
		return nil, fmt.Errorf(
			"OpenSSH emitted diagnostics while resolving configuration: %s",
			diagnostics,
		)
	}
	return stdout.Bytes(), nil
}

func effectiveLocalForward(spec ClientSpec) string {
	listen := fmt.Sprintf("[%s]:%d", spec.ListenAddress.Unmap(), spec.ListenPort)
	target := fmt.Sprintf("[%s]:%d", spec.TargetAddress.Unmap(), spec.TargetPort)
	return listen + " " + target
}

func managementListenPort(listenPort uint16) uint16 {
	if listenPort == 0 || listenPort == 65535 {
		return 0
	}
	return listenPort + 1
}

func effectiveManagementForward(spec ClientSpec) string {
	listen := fmt.Sprintf("[%s]:%d", spec.ListenAddress.Unmap(), managementListenPort(spec.ListenPort))
	return listen + " " + fmt.Sprintf("[127.0.0.1]:%d", enrollment.DefaultManagementPort)
}

func parseEffectiveOptions(output []byte) (map[string][]string, error) {
	options := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, " ")
		if !found || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("OpenSSH produced malformed effective configuration output")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		options[key] = append(options[key], strings.TrimSpace(value))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read effective OpenSSH configuration: %w", err)
	}
	return options, nil
}
