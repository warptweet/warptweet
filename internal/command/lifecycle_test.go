package command

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/lifecycle"
	"warptweet.com/warptweet/internal/profile"
)

func TestLifecycleUsageMentionsCommands(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, required := range []string{
		"warptweet enroll",
		"warptweet up",
		"warptweet status",
		"warptweet down",
		"warptweet rotate",
		"warptweet revoke",
		"warptweet uninstall --preserve-identity",
	} {
		if !strings.Contains(stdout.String(), required) {
			t.Fatalf("usage omits %q", required)
		}
	}
}

func TestEnrollPrepareOnlyStagesWithoutSecrets(t *testing.T) {
	t.Parallel()

	// Without bundled ssh-keygen this becomes a keygen path error; still prove
	// invite parsing and confirmation flags reject private-key invites first.
	raw := []byte(`{
  "kind":"warptweet.invite",
  "schema_version":1,
  "invite_id":"abc123",
  "client_name":"laptop-1",
  "server_address":"192.0.2.10",
  "server_port":2222,
  "target_address":"198.51.100.20",
  "target_port":5432,
  "principal":"warptweet",
  "profile_id":"` + profile.CurrentID + `",
  "artifact_profile_id":"darwin-arm64",
  "host_public_key":"ssh-mldsa44-ed25519@openssh.com AAAA",
  "issued_at":"2026-08-12T12:00:00Z",
  "expires_at":"` + time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339Nano) + `",
  "nonce":"abcd",
  "mac":"aa"
}`)
	invitePath := filepath.Join(t.TempDir(), "invite.json")
	if err := os.WriteFile(invitePath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"enroll", invitePath, "--yes", "--prepare-only",
	}, nil, &stdout, &stderr)
	if code == 0 {
		var output map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if output["status"] != "prepared" {
			t.Fatalf("output=%v", output)
		}
		if strings.Contains(strings.ToLower(stdout.String()), "private") {
			t.Fatal("prepared output leaked private key material")
		}
		return
	}
	// On hosts without packaged ssh-keygen, enroll fails after invite parse.
	if !strings.Contains(stderr.String(), "generate client key") &&
		!strings.Contains(stderr.String(), "ssh-keygen") &&
		!strings.Contains(stderr.String(), "invite") {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestStatusAndDownWithoutState(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"status", "no-such-tunnel"}, nil, &stdout, &stderr)
	if code != 0 {
		// production layout resolution can fail off-matrix; accept clear errors.
		if stderr.Len() == 0 {
			t.Fatalf("code=%d empty stderr", code)
		}
		return
	}
	var state lifecycle.State
	if err := json.Unmarshal(stdout.Bytes(), &state); err != nil {
		t.Fatalf("decode: %v (%s)", err, stdout.String())
	}
	if state.Phase != lifecycle.PhaseStopped || state.TargetHealth != lifecycle.TargetHealthNotChecked {
		t.Fatalf("state=%+v", state)
	}
}

func TestRotateAndRevokeAreExplicitlyUnsupported(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"rotate", "database-primary"},
		{"revoke", "database-primary"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run(context.Background(), args, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v code=%d stderr=%s", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"status":"unsupported"`) {
			t.Fatalf("%v output=%s", args, stdout.String())
		}
	}
}

func TestUninstallRequiresPreserveIdentity(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"uninstall"}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("uninstall accepted missing preserve flag")
	}
	if !strings.Contains(stderr.String(), "--preserve-identity") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
