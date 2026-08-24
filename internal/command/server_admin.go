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
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/server"
)

const (
	inviteSecretPath     = "/etc/warptweet/invite.mac-key"
	inviteDirectory      = "/var/lib/warptweet/invites"
	serverStateDirectory = "/var/lib/warptweet/server"
)

func runServer(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("server requires an internal subcommand: enroll-listen, mgmt-listen, data-plane, host-sign, accept-enrollment, revoke, status, clock-recover")
	}
	switch arguments[0] {
	case "enroll-listen":
		return runServerEnrollListen(ctx, arguments[1:], stdout, stderr)
	case "mgmt-listen":
		return runServerMgmtListen(ctx, arguments[1:], stdout, stderr)
	case "data-plane":
		return runServerDataPlane(ctx, arguments[1:], stdout, stderr)
	case "host-sign":
		return runServerHostSign(ctx, arguments[1:], stdout, stderr)
	case "accept-enrollment":
		return runServerAcceptEnrollment(ctx, arguments[1:], stdout, stderr)
	case "revoke":
		return runServerRevoke(arguments[1:], stdout, stderr)
	case "status":
		return runServerStatus(ctx, arguments[1:], stdout, stderr)
	case "clock-recover":
		return runServerClockRecover(ctx, arguments[1:], stdout, stderr)
	case "init", "invite":
		return outcome.Replaced("server "+arguments[0], "warptweet host --to <port|ip:port>")
	default:
		return fmt.Errorf("unknown server subcommand %q", arguments[0])
	}
}

func runServerRevoke(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) != 1 {
		return errors.New("server revoke requires exactly one client-id or invite-id")
	}
	id := arguments[0]
	if !enrollment.IsHexID(id) {
		return errors.New("revoke id must be a hexadecimal identifier")
	}
	now := time.Now().UTC()
	record, err := enrollment.Load(inviteDirectory, id)
	if err == nil {
		if record.Status == enrollment.StatusIssued || record.Status == enrollment.StatusCancelled ||
			(record.Status == enrollment.StatusExpired && record.ClientID == "") {
			cancelled, err := enrollment.Cancel(inviteDirectory, id, now)
			if err != nil {
				return err
			}
			return writeJSON(stdout, map[string]any{
				"status":    "cancelled",
				"invite_id": cancelled.InviteID,
				"prior":     record.Status,
			})
		}
		if record.ClientID == "" {
			return errors.New("consumed invite has no client_id")
		}
		client, err := revokeGrantAsHost(record.ClientID, now)
		if err != nil {
			return err
		}
		if _, err := enrollment.Revoke(inviteDirectory, id, now); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{
			"status":    "revoked",
			"invite_id": id,
			"client_id": client.ClientID,
			"prior":     record.Status,
		})
	}
	if !os.IsNotExist(err) {
		return err
	}
	if _, err := enrollment.LoadClient(installlayout.ClientsDirectory, id); err == nil {
		client, err := revokeGrantAsHost(id, now)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{
			"status":    "revoked",
			"client_id": client.ClientID,
		})
	} else if !os.IsNotExist(err) {
		return err
	}
	return fmt.Errorf("unknown invite or client %q", id)
}

func revokeGrantAsHost(clientID string, now time.Time) (enrollment.ClientRecord, error) {
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return enrollment.ClientRecord{}, err
	}
	authority := productionGrantAuthority()
	return enrollment.RevokeClientAsHost(
		installlayout.ClientsDirectory,
		clientID,
		now,
		func(publicKey string) error {
			return removeAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, publicKey)
		},
		enrollment.SessionEnforcement{
			TerminateSession:  authority.Terminate,
			VerifySessionGone: authority.VerifyGone,
		},
	)
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
		status["listen"] = manifest.Network.Data.Listen.AddrPort().String()
		status["target"] = fmt.Sprintf("%s:%d", manifest.Target.Address, manifest.Target.Port)
		status["dedicated_user"] = manifest.DedicatedUser
		status["manifest"] = "present"
		if addr := manifest.Network.Enrollment.Listen.Address; addr.IsValid() && !addr.IsUnspecified() {
			if url, err := enrollment.EnrollmentURL(addr.String(), uint16(manifest.Network.Enrollment.Listen.Port)); err == nil {
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
	status["clock_blocked"] = grant.ClockIsBlocked(installlayout.HostClockBlockedPath)
	return writeJSON(stdout, status)
}

func runServerClockRecover(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("server clock-recover accepts no arguments")
	}
	_ = stderr
	if _, err := grant.ObserveClock(installlayout.HostClockObservationPath, time.Now().UTC()); err != nil {
		return fmt.Errorf("clock is still untrusted: %w", err)
	}
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	if err := reconcileManagedAuthorizations(manifest); err != nil {
		return fmt.Errorf("reconcile managed authorizations: %w", err)
	}
	if err := grant.ClearBlockedClock(installlayout.HostClockBlockedPath); err != nil {
		return err
	}
	if _, err := ensureSSHDStarted(ctx, manifest, false); err != nil {
		return fmt.Errorf("restart data plane: %w", err)
	}
	return writeJSON(stdout, map[string]any{"status": "clock_recovered"})
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
	return writeFileAtomic(path, nil, 0o644)
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
