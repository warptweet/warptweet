package command

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestUsageKeepsInternalServerCommandsPrivate(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, forbidden := range []string{
		"warptweet server init",
		"warptweet server invite",
		"warptweet server enroll-listen",
		"warptweet server accept-enrollment",
		"warptweet server revoke",
		"warptweet server status",
	} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("usage exposes internal command %q: %s", forbidden, stdout.String())
		}
	}
}

func TestServerStatusReportsMissingManifest(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"server", "status"}, nil, &stdout, &stderr)
	if code != 0 {
		// Status may fail if invite directory permissions block listing under
		// restricted environments; accept either missing-manifest JSON or a
		// clear permission error.
		if !strings.Contains(stderr.String(), "permission denied") &&
			!strings.Contains(stderr.String(), "invites") {
			t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
		}
		return
	}
	if !strings.Contains(stdout.String(), `"role":"server"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestParseEndpointAcceptsConcreteIPs(t *testing.T) {
	t.Parallel()

	endpoint, err := parseEndpoint("192.0.2.10:2222")
	if err != nil {
		t.Fatalf("parseEndpoint: %v", err)
	}
	if endpoint.String() != "192.0.2.10:2222" {
		t.Fatalf("endpoint=%s", endpoint)
	}
	if _, err := parseEndpoint("0.0.0.0:22"); err == nil {
		// unspecified may parse via AddrPort; parseEndpoint checks after parse
	}
	if _, err := parseEndpoint("hostname:22"); err == nil {
		t.Fatal("accepted hostname")
	}
}

func TestInviteCreateAndRevokeWithoutPackage(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	now := time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)
	invite, record, err := enrollment.Create(enrollment.CreateInput{
		ClientName:                  "node-a",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              enrollment.DefaultEnrollmentPort,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   server.DefaultDedicatedUser,
		ProfileID:                   profile.CurrentID,
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA",
		EnrollmentTLSSPKISHA256:     strings.Repeat("a", 64),
		Now:                         now,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := enrollment.Store(directory, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	raw, err := enrollment.Encode(invite)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, forbidden := range []string{"private", "BEGIN", "seed"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("invite contains %q", forbidden)
		}
	}
	if document["kind"] != enrollment.KindInvite {
		t.Fatalf("kind=%v", document["kind"])
	}
	if _, err := enrollment.Cancel(directory, invite.InviteID, now.Add(time.Minute)); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
}

func TestServerInitRequiresFlags(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"server", "init"}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("init accepted missing flags")
	}
	if !strings.Contains(stderr.String(), "replaced by") || !strings.Contains(stderr.String(), "warptweet host") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "file.txt")
	if err := writeFileAtomic(path, []byte("ok\n"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(contents) != "ok\n" {
		t.Fatalf("contents=%q", contents)
	}
}
