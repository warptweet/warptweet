// Command warptweet-provisioner is the privileged macOS activation helper.
// It exposes a tiny typed request surface and never accepts shell commands,
// arbitrary paths, OpenSSH options, or service definition fragments.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"warptweet.com/warptweet/internal/command"
	"warptweet.com/warptweet/internal/installlayout"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func geteuid() int {
	return os.Geteuid()
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		writeUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "version":
		_, _ = fmt.Fprintf(stdout, "warptweet-provisioner %s\n", command.Version)
		return 0
	case "verify-layout":
		if err := verifyLayout(); err != nil {
			_, _ = fmt.Fprintf(stderr, "warptweet-provisioner: %v\n", err)
			return 1
		}
		return writeJSON(stdout, map[string]any{
			"status":               "layout_ready",
			"application_support":  installlayout.DarwinApplicationSupportRoot,
			"ssh_path":             installlayout.DarwinSSHPath,
			"client_manifest_path": installlayout.DarwinClientManifestPath,
			"service_user":         installlayout.DarwinClientServiceUser,
			"service_group":        installlayout.DarwinClientServiceGroup,
			"runtime_root":         installlayout.DarwinClientRuntimeRoot,
		})
	case "help", "-h", "--help":
		writeUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "warptweet-provisioner: unknown request %q\n", arguments[0])
		writeUsage(stderr)
		return 2
	}
}

func verifyLayout() error {
	if os.Geteuid() != 0 {
		return errors.New("verify-layout requires root")
	}
	requiredDirs := []string{
		installlayout.DarwinApplicationSupportRoot,
		filepath.Dir(installlayout.DarwinControllerPath),
		installlayout.DarwinOpenSSHPrefix,
		filepath.Dir(installlayout.DarwinSSHPath),
		installlayout.DarwinClientStateRoot,
		installlayout.DarwinClientIdentityDirectory,
		installlayout.DarwinClientTrustDirectory,
		installlayout.DarwinClientRuntimeRoot,
	}
	for _, path := range requiredDirs {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("missing required directory %q: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("required path %q must not be a symlink", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("required path %q is not a directory", path)
		}
	}
	requiredFiles := []string{
		installlayout.DarwinControllerPath,
		installlayout.DarwinSSHPath,
		installlayout.DarwinSSHKeygenPath,
		installlayout.DarwinClientGlobalKnownHostsPath,
	}
	for _, path := range requiredFiles {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("missing required file %q: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("required path %q must not be a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("required path %q is not a regular file", path)
		}
	}
	for _, forbidden := range []string{
		filepath.Join(installlayout.DarwinOpenSSHPrefix, "sbin", "sshd"),
		filepath.Join(installlayout.DarwinOpenSSHPrefix, "libexec", "sshd-auth"),
		filepath.Join(installlayout.DarwinOpenSSHPrefix, "libexec", "sshd-session"),
	} {
		if _, err := os.Lstat(forbidden); err == nil {
			return fmt.Errorf("forbidden server helper present at %q", forbidden)
		}
	}
	emptyInfo, err := os.Lstat(installlayout.DarwinClientGlobalKnownHostsPath)
	if err != nil {
		return err
	}
	if emptyInfo.Size() != 0 {
		return errors.New("known_hosts.empty must be exactly empty")
	}
	return nil
}

func writeJSON(writer io.Writer, value any) int {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}

func writeUsage(writer io.Writer) {
	_, _ = io.WriteString(writer, strings.TrimSpace(`
warptweet-provisioner: privileged WarpTweet activation helper

Usage:
  warptweet-provisioner version
  warptweet-provisioner verify-layout
`)+"\n")
}
