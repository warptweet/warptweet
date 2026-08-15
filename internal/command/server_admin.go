package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const (
	inviteSecretPath     = "/etc/warptweet/invite.mac-key"
	inviteDirectory      = "/var/lib/warptweet/invites"
	serverStateDirectory = "/var/lib/warptweet/server"
)

func runServer(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("server requires a subcommand: init, invite, enroll-listen, accept-enrollment, revoke, status")
	}
	switch arguments[0] {
	case "init":
		return runServerInit(ctx, arguments[1:], stdout, stderr)
	case "invite":
		return runServerInvite(ctx, arguments[1:], stdout, stderr)
	case "enroll-listen":
		return runServerEnrollListen(ctx, arguments[1:], stdout, stderr)
	case "accept-enrollment":
		return runServerAcceptEnrollment(ctx, arguments[1:], stdout, stderr)
	case "revoke":
		return runServerRevoke(arguments[1:], stdout, stderr)
	case "status":
		return runServerStatus(ctx, arguments[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown server subcommand %q", arguments[0])
	}
}

func runServerInit(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server init", stderr)
	listen := onceStringFlag{name: "--listen"}
	target := onceStringFlag{name: "--target"}
	flags.Var(&listen, "listen", "numeric server listen address:port")
	flags.Var(&target, "target", "numeric authorized target address:port")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if listen.value == "" || target.value == "" {
		return errors.New("server init requires --listen and --target")
	}
	listenEndpoint, err := parseEndpoint(listen.value)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	targetEndpoint, err := parseEndpoint(target.value)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(installlayout.ServerHostKeyPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(installlayout.AuthorizedKeysDirectory, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(installlayout.ServerManifestPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(inviteDirectory, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(serverStateDirectory, 0o700); err != nil {
		return err
	}

	if _, err := os.Lstat(installlayout.ServerHostKeyPath); err == nil {
		return fmt.Errorf("host key already exists at %s", installlayout.ServerHostKeyPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	keygen := installlayout.SSHKeygenPath
	if _, err := os.Stat(keygen); err != nil {
		return fmt.Errorf("bundled ssh-keygen is required at %s: %w", keygen, err)
	}
	cmd := exec.CommandContext(
		ctx,
		keygen,
		"-t", "mldsa44-ed25519",
		"-f", installlayout.ServerHostKeyPath,
		"-N", "",
		"-C", "warptweet-host",
	)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("generate host key: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(installlayout.ServerHostKeyPath, 0o600); err != nil {
		return err
	}
	if err := os.Chown(installlayout.ServerHostKeyPath, 0, 0); err != nil && os.Geteuid() == 0 {
		return err
	}

	publicKey, err := deriveHostPublicKey(ctx, installlayout.ServerHostKeyPath)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256([]byte(publicKey))
	if err := os.WriteFile(installlayout.ServerHostKeyPath+".pub", append([]byte(publicKey), '\n'), 0o644); err != nil {
		return err
	}

	secret, err := enrollment.GenerateSecret()
	if err != nil {
		return err
	}
	if err := enrollment.WriteSecret(inviteSecretPath, secret); err != nil {
		return err
	}

	sshdDigest := strings.Repeat("0", 64)
	bundleDigest := strings.Repeat("0", 64)
	if digest, err := fileSHA256(installlayout.SSHDPath); err == nil {
		sshdDigest = digest
	}
	if digest, err := fileSHA256(installlayout.OpenSSHBundleManifestPath); err == nil {
		bundleDigest = digest
	}

	manifest := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            sshdDigest,
		OpenSSHBundleManifestSHA256: bundleDigest,
		Listen: server.Endpoint{
			Address: listenEndpoint.Addr(),
			Port:    server.Port(listenEndpoint.Port()),
		},
		Target: server.Endpoint{
			Address: targetEndpoint.Addr(),
			Port:    server.Port(targetEndpoint.Port()),
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: filepath.Join(installlayout.AuthorizedKeysDirectory, server.DefaultDedicatedUser),
	}
	if err := server.Validate(manifest); err != nil {
		return err
	}
	if err := writeServerManifestAtomic(installlayout.ServerManifestPath, manifest); err != nil {
		return err
	}
	if err := os.WriteFile(manifest.AuthorizedKeysPath, nil, 0o600); err != nil {
		return err
	}

	return writeJSON(stdout, map[string]any{
		"status":                 "initialized",
		"host_key_path":          installlayout.ServerHostKeyPath,
		"host_public_key_sha256": hex.EncodeToString(fingerprint[:]),
		"manifest_path":          installlayout.ServerManifestPath,
		"invite_secret_path":     inviteSecretPath,
		"listen":                 listenEndpoint.String(),
		"target":                 targetEndpoint.String(),
		"dedicated_user":         manifest.DedicatedUser,
	})
}

func runServerInvite(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server invite", stderr)
	target := onceStringFlag{name: "--target"}
	name := onceStringFlag{name: "--name"}
	flags.Var(&target, "target", "numeric authorized target address:port")
	flags.Var(&name, "name", "client name label")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if target.value == "" || name.value == "" {
		return errors.New("server invite requires --target and --name")
	}
	targetEndpoint, err := parseEndpoint(target.value)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	label := enrollment.SanitizeInviteLabel(name.value)
	invite, record, err := mintServerInvite(ctx, label, targetEndpoint, manifest, "")
	if err != nil {
		return err
	}
	if err := enrollment.Store(inviteDirectory, record); err != nil {
		return err
	}
	raw, err := enrollment.Encode(invite)
	if err != nil {
		return err
	}
	var inviteObject any
	if err := json.Unmarshal(raw, &inviteObject); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"status":     "issued",
		"invite_id":  invite.InviteID,
		"expires_at": invite.ExpiresAt,
		"invite":     inviteObject,
	})
}

func runServerRevoke(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) != 1 {
		return errors.New("server revoke requires exactly one client-id or invite-id")
	}
	id := arguments[0]
	if id == "" {
		return errors.New("revoke id is required")
	}
	// Prefer invite-id revocation when a matching invite exists.
	if record, err := enrollment.Load(inviteDirectory, id); err == nil {
		revoked, err := enrollment.Revoke(inviteDirectory, id, time.Now().UTC())
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{
			"status":    "revoked",
			"invite_id": revoked.InviteID,
			"client_id": revoked.ClientID,
			"prior":     record.Status,
		})
	}
	// Otherwise treat the argument as a managed client marker path suffix and
	// clear authorized_keys transactionally when it matches the only entry.
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	if err := clearAuthorizedKeys(manifest.AuthorizedKeysPath); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"status":               "authorization_cleared",
		"client_id":            id,
		"authorized_keys_path": manifest.AuthorizedKeysPath,
	})
}

func runServerStatus(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("server status accepts no arguments")
	}
	_ = ctx
	_ = stderr
	status := map[string]any{
		"role":             "server",
		"manifest_path":    installlayout.ServerManifestPath,
		"host_key_path":    installlayout.ServerHostKeyPath,
		"invite_directory": inviteDirectory,
		"enroll_port":      enrollment.DefaultEnrollmentPort,
	}
	if manifest, err := server.Load(installlayout.ServerManifestPath); err == nil {
		status["profile_id"] = manifest.ProfileID
		status["listen"] = fmt.Sprintf("%s:%d", manifest.Listen.Address, manifest.Listen.Port)
		status["target"] = fmt.Sprintf("%s:%d", manifest.Target.Address, manifest.Target.Port)
		status["dedicated_user"] = manifest.DedicatedUser
		status["manifest"] = "present"
		if addr := manifest.Listen.Address; addr.IsValid() && !addr.IsUnspecified() {
			if url, err := enrollment.EnrollmentURL(addr.String(), enrollment.DefaultEnrollmentPort); err == nil {
				status["enroll_url"] = url
			}
		}
	} else {
		status["manifest"] = "missing"
	}
	if _, err := os.Lstat(installlayout.ServerHostKeyPath); err == nil {
		status["host_key"] = "present"
	} else {
		status["host_key"] = "missing"
	}
	records, err := enrollment.List(inviteDirectory)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, record := range records {
		counts[record.Status]++
	}
	status["invites"] = counts
	status["invite_total"] = len(records)
	clients, err := enrollment.ListClients(installlayout.ClientsDirectory)
	if err != nil {
		status["clients"] = "missing"
		status["client_total"] = 0
	} else {
		clientCounts := map[string]int{}
		for _, client := range clients {
			clientCounts[client.Status]++
		}
		status["clients"] = clientCounts
		status["client_total"] = len(clients)
	}
	return writeJSON(stdout, status)
}

func parseEndpoint(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		// Allow bare IPv4:port with unbracketed form only.
		host, portText, ok := strings.Cut(value, ":")
		if !ok {
			return netip.AddrPort{}, err
		}
		address, addrErr := netip.ParseAddr(host)
		if addrErr != nil {
			return netip.AddrPort{}, err
		}
		port, portErr := strconv.ParseUint(portText, 10, 16)
		if portErr != nil || port == 0 {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(address, uint16(port)), nil
	}
	if endpoint.Addr().IsUnspecified() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return netip.AddrPort{}, errors.New("endpoint must be a concrete unzoned IP and nonzero port")
	}
	return endpoint, nil
}

func deriveHostPublicKey(ctx context.Context, privateKeyPath string) (string, error) {
	cmd := exec.CommandContext(ctx, installlayout.SSHKeygenPath, "-y", "-f", privateKeyPath)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("derive host public key: %w", err)
	}
	line := strings.TrimSpace(string(output))
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return "", errors.New("host public key output must be exactly one line")
	}
	return line, nil
}

func fileSHA256(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:]), nil
}

func writeServerManifestAtomic(path string, manifest server.Config) error {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeFileAtomic(path, encoded, 0o644)
}

func clearAuthorizedKeys(path string) error {
	return writeFileAtomic(path, nil, 0o600)
}

func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".wt-server-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if len(contents) > 0 {
		if _, err := temp.Write(contents); err != nil {
			_ = temp.Close()
			return err
		}
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
