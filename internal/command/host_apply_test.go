package command

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
)

func TestApplyHostInterruptionResumesExactlyOneInvite(t *testing.T) {
	t.Parallel()

	for _, step := range []string{
		hostStepCertWrite,
		hostStepManifestWrite,
		hostStepDataPlaneRestart,
		hostStepEnrollmentRestart,
		hostStepReadinessVerify,
		hostStepInviteRecord,
	} {
		step := step
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			env, input := newTestHostApply(t)
			env.InterruptAfter = step
			_, err := applyHostConfiguration(context.Background(), env, input)
			if !errors.Is(err, errHostInterrupted) {
				t.Fatalf("first apply error=%v, want interrupted after %s", err, step)
			}
			env.InterruptAfter = ""
			result, err := applyHostConfiguration(context.Background(), env, input)
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if result.Manifest.Network.PublishedEndpointGeneration != 1 {
				t.Fatalf("generation=%d", result.Manifest.Network.PublishedEndpointGeneration)
			}
			issued, err := enrollment.UnusedIssuedForGeneration(env.InviteDir, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(issued) != 1 || issued[0].InviteID != result.Invite.InviteID {
				t.Fatalf("issued=%+v invite=%s", issued, result.Invite.InviteID)
			}
			if step == hostStepInviteRecord && !result.ResumedInvite {
				t.Fatal("invite-record interruption did not resume the issued blob")
			}
		})
	}
}

func TestApplyHostReconcilesWhenAppliedReceiptMissing(t *testing.T) {
	t.Parallel()

	env, input := newTestHostApply(t)
	input.NoInvite = true
	first, err := applyHostConfiguration(context.Background(), env, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(appliedReceiptPath(env.StateDir)); err != nil {
		t.Fatal(err)
	}
	var dataRestarts, enrollRestarts int
	env.ApplyDataPlane = func(restart bool, endpoint netip.AddrPort) (string, error) {
		if restart {
			dataRestarts++
		}
		return "ok", nil
	}
	env.ApplyEnrollment = func(restart bool, endpoint netip.AddrPort, pin string) (string, error) {
		if restart {
			enrollRestarts++
		}
		return "ok", nil
	}
	second, err := applyHostConfiguration(context.Background(), env, input)
	if err != nil {
		t.Fatal(err)
	}
	if dataRestarts != 1 || enrollRestarts != 1 {
		t.Fatalf("reconcile restarts data=%d enroll=%d", dataRestarts, enrollRestarts)
	}
	if second.Manifest.Network.PublishedEndpointGeneration != first.Manifest.Network.PublishedEndpointGeneration {
		t.Fatal("reconcile bumped generation")
	}
}

func TestBindOnlyChangeDoesNotIncrementGenerationOrRefuse(t *testing.T) {
	t.Parallel()

	env, input := newTestHostApply(t)
	first, err := applyHostConfiguration(context.Background(), env, input)
	if err != nil {
		t.Fatal(err)
	}
	input.Flags.Listen = onceStringFlag{name: "--listen", value: "192.0.2.10:2222", set: true}
	input.NoInvite = true
	second, err := applyHostConfiguration(context.Background(), env, input)
	if err != nil {
		t.Fatalf("bind-only change refused: %v", err)
	}
	if second.Manifest.Network.PublishedEndpointGeneration != first.Manifest.Network.PublishedEndpointGeneration {
		t.Fatalf("bind-only change bumped generation %d -> %d", first.Manifest.Network.PublishedEndpointGeneration, second.Manifest.Network.PublishedEndpointGeneration)
	}
}

func TestPublishedLocatorChangeRefusedWhileInviteIssued(t *testing.T) {
	t.Parallel()

	env, input := newTestHostApply(t)
	first, err := applyHostConfiguration(context.Background(), env, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Invite.InviteID == "" {
		t.Fatal("expected minted invite")
	}
	input.Flags.Advertise = onceStringFlag{name: "--advertise", value: "34.20.174.226:2222", set: true}
	input.NoInvite = true
	if _, err := applyHostConfiguration(context.Background(), env, input); err == nil {
		t.Fatal("accepted published locator change with issued invite")
	} else if !strings.Contains(err.Error(), "published endpoints") || !strings.Contains(err.Error(), first.Invite.InviteID) {
		t.Fatalf("error=%v", err)
	}
}

func TestConcurrentHostApplySerializesAndMintsOnce(t *testing.T) {
	t.Parallel()

	env, input := newTestHostApply(t)
	errCh := make(chan error, 2)
	var mints atomic.Int32
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			errCh <- withHostOperationLockAt(env.StateDir, func() error {
				result, err := applyHostConfiguration(context.Background(), env, input)
				if err != nil {
					return err
				}
				if result.Invite.InviteID != "" && !result.ResumedInvite {
					mints.Add(1)
				}
				return nil
			})
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	issued, err := enrollment.UnusedIssuedForGeneration(env.InviteDir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(issued) != 1 {
		t.Fatalf("issued count=%d", len(issued))
	}
	if mints.Load() != 1 {
		t.Fatalf("mints=%d", mints.Load())
	}
}

func newTestHostApply(t *testing.T) (hostApplyEnv, hostApplyInput) {
	t.Helper()
	root := t.TempDir()
	certDir := filepath.Join(root, "enrollment")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	pin, _, _, err := enrollment.EnsureTLSIdentity(certPath, keyPath, []net.IP{net.ParseIP("10.168.0.2")}, now)
	if err != nil {
		t.Fatal(err)
	}
	env := hostApplyEnv{
		ManifestPath: filepath.Join(root, "server.wt"),
		StateDir:     filepath.Join(root, "state"),
		InviteDir:    filepath.Join(root, "invites"),
		ClientsDir:   filepath.Join(root, "clients"),
		CertPath:     certPath,
		KeyPath:      keyPath,
		Now:          now,
		Discover: func() (netip.Addr, error) {
			return netip.MustParseAddr("10.168.0.2"), nil
		},
		ProbeTCP: func(netip.AddrPort) bool { return true },
		EnsureIdentity: func(context.Context) (string, bool, error) {
			return "ssh-mldsa44-ed25519@openssh.com AAAA host", true, nil
		},
		EnsureTLS: func([]net.IP, time.Time) (string, bool, bool, error) {
			return pin, false, false, nil
		},
		ApplyDataPlane:   func(bool, netip.AddrPort) (string, error) { return "direct_ready", nil },
		ApplyEnrollment:  func(bool, netip.AddrPort, string) (string, error) { return "started", nil },
		AllowTestDigests: true,
	}
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(env.InviteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(env.ClientsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	input := hostApplyInput{
		Target: netip.MustParseAddrPort("127.0.0.1:5432"),
		Flags: hostPublicationFlags{
			Listen: onceStringFlag{name: "--listen", value: "10.168.0.2:2222", set: true},
		},
		Label:                "laptop-1",
		AuthorizationSeconds: 3600,
	}
	return env, input
}
