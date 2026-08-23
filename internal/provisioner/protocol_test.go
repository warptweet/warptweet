package provisioner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/installlayout"
)

func TestValidateRequestAcceptsOnlyActionSpecificFields(t *testing.T) {
	t.Parallel()

	invite := json.RawMessage(`{"kind":"warptweet.invite"}`)
	tests := []struct {
		name    string
		request Request
		wantErr string
	}{
		{name: "enroll", request: Request{Version: 1, Action: ActionEnroll, Invite: invite}},
		{name: "enroll once", request: Request{Version: 1, Action: ActionEnroll, Invite: invite, Once: true}, wantErr: "only for up"},
		{name: "up", request: Request{Version: 1, Action: ActionUp, TunnelID: "db-1"}},
		{name: "repair", request: Request{Version: 1, Action: ActionRepair, TunnelID: "db-1"}},
		{name: "up proof", request: Request{Version: 1, Action: ActionUp, TunnelID: "db-1", Proof: json.RawMessage(`{}`)}, wantErr: "another action"},
		{name: "status all", request: Request{Version: 1, Action: ActionStatus}},
		{name: "status once", request: Request{Version: 1, Action: ActionStatus, Once: true}, wantErr: "another action"},
		{name: "down once", request: Request{Version: 1, Action: ActionDown, TunnelID: "db-1", Once: true}, wantErr: "only for"},
		{name: "invalid id", request: Request{Version: 1, Action: ActionUp, TunnelID: "../db"}, wantErr: "invalid tunnel_id"},
		{name: "unknown action", request: Request{Version: 1, Action: "exec", TunnelID: "db-1"}, wantErr: "unsupported"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRequest(test.request)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateRequest: %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateRequest error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestDecodeSingleJSONRejectsUnknownTrailingAndOversizedInput(t *testing.T) {
	t.Parallel()

	var response Response
	if err := decodeSingleJSON(strings.NewReader(`{"ok":true}`), 64, &response); err != nil {
		t.Fatalf("decode valid response: %v", err)
	}
	if !response.OK {
		t.Fatal("valid response did not decode")
	}
	for _, input := range []string{
		`{"ok":true,"unknown":1}`,
		`{"ok":true}{"ok":false}`,
		strings.Repeat(" ", 65),
	} {
		response = Response{}
		if err := decodeSingleJSON(strings.NewReader(input), 64, &response); err == nil {
			t.Fatalf("accepted invalid JSON framing %q", input)
		}
	}
}

func TestSafeRemoteErrorRemovesControlCharacters(t *testing.T) {
	t.Parallel()

	got := safeRemoteError("  failed\n\x1b[31msecret\r\n  ")
	if strings.ContainsAny(got, "\n\r\t\x1b") || got != "failed [31msecret" {
		t.Fatalf("safeRemoteError = %q", got)
	}
}

func TestTunnelStartActionsIncludeRepair(t *testing.T) {
	t.Parallel()

	if !isTunnelStartAction(ActionUp) || !isTunnelStartAction(ActionRepair) {
		t.Fatal("up and repair must start the projected tunnel")
	}
	for _, action := range []string{ActionEnroll, ActionConnect, ActionStatus, ActionDown, ActionRotate, ActionRevoke, "exec"} {
		if isTunnelStartAction(action) {
			t.Fatalf("%q must not start a tunnel", action)
		}
	}
}

func TestEnrollControllerArgsForwardProof(t *testing.T) {
	t.Parallel()

	request := Request{
		PrepareOnly:   true,
		ListenPort:    15432,
		RestartPolicy: "manual",
		Proof:         json.RawMessage(`{"ok":true}`),
	}
	got := enrollControllerArgs("/tmp/invite", "/tmp/proof", request)
	want := []string{"enroll", "--yes", "--prepare-only", "--listen-port", "15432", "--restart", "manual", "--proof", "/tmp/proof", "/tmp/invite"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%v want=%v", got, want)
	}
	if got := enrollControllerArgs("/tmp/invite", "", Request{}); !reflect.DeepEqual(got, []string{"enroll", "--yes", "/tmp/invite"}) {
		t.Fatalf("args without proof=%v", got)
	}
}

func TestMaterializeEnrollInputsWritesProof(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	invitePath, proofPath, err := materializeEnrollInputs(root, Request{
		Invite: json.RawMessage(`{"kind":"warptweet.invite"}`),
		Proof:  json.RawMessage(`{"proof":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(invitePath) != root || filepath.Dir(proofPath) != root {
		t.Fatalf("paths=%s %s", invitePath, proofPath)
	}
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(proof) != "{\"proof\":true}\n" {
		t.Fatalf("proof=%q", proof)
	}
}

func TestRotateAndRevokeDoNotStopTheTunnelFirst(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	for _, name := range []string{"server.go", "server_linux.go"} {
		contents := string(readFile(t, filepath.Join(root, name)))
		block := actionBlock(contents, "ActionRotate, ActionRevoke")
		if block == "" {
			t.Fatalf("%s missing rotate/revoke action block", name)
		}
		if strings.Contains(block, "stopTunnel") || strings.Contains(block, "projectTunnel") {
			t.Fatalf("%s still stops the tunnel before rotate/revoke", name)
		}
		if !strings.Contains(block, "executeController") {
			t.Fatalf("%s rotate/revoke does not invoke the controller", name)
		}
	}
}

func actionBlock(source, label string) string {
	index := strings.Index(source, "case "+label+":")
	if index < 0 {
		return ""
	}
	rest := source[index:]
	body := rest[len("case "+label+":"):]
	end := len(body)
	for _, marker := range []string{"\n\tcase ", "\n\tdefault:"} {
		if at := strings.Index(body, marker); at >= 0 && at < end {
			end = at
		}
	}
	return body[:end]
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func TestSocketPathMatchesPlatformLayout(t *testing.T) {
	t.Parallel()

	path := SocketPath()
	switch runtime.GOOS {
	case "darwin":
		if path != installlayout.DarwinProvisionerSocket {
			t.Fatalf("socket=%q", path)
		}
	default:
		if path != installlayout.LinuxProvisionerSocket {
			t.Fatalf("socket=%q", path)
		}
	}
}
