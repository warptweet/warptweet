package provisioner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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

func TestRenderTunnelPlistIsClosedAndDeterministic(t *testing.T) {
	t.Parallel()

	first, label, err := renderTunnelPlist("db-1", false)
	if err != nil {
		t.Fatalf("renderTunnelPlist: %v", err)
	}
	second, secondLabel, err := renderTunnelPlist("db-1", false)
	if err != nil {
		t.Fatalf("renderTunnelPlist repeat: %v", err)
	}
	if label != "com.warptweet.tunnel.db-1" || secondLabel != label || !bytes.Equal(first, second) {
		t.Fatalf("nondeterministic plist or label %q/%q", label, secondLabel)
	}
	text := string(first)
	for _, required := range []string{
		"<string>/Library/Application Support/WarpTweet/bin/warptweet</string>",
		"<string>run</string>",
		"<string>--managed-lifecycle</string>",
		"<string>_warptweet</string>",
		"<key>KeepAlive</key><false/>",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("plist omits %q", required)
		}
	}
	if strings.Contains(text, "--once") {
		t.Fatal("default managed plist unexpectedly disables bounded in-process restart")
	}
	once, _, err := renderTunnelPlist("db-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(once), "<string>--once</string>") != 1 {
		t.Fatal("once plist does not contain exactly one --once argument")
	}
	if _, _, err := renderTunnelPlist(`db</string>`, false); err == nil {
		t.Fatal("plist renderer accepted XML injection")
	}
}

func TestSafeRemoteErrorRemovesControlCharacters(t *testing.T) {
	t.Parallel()

	got := safeRemoteError("  failed\n\x1b[31msecret\r\n  ")
	if strings.ContainsAny(got, "\n\r\t\x1b") || got != "failed [31msecret" {
		t.Fatalf("safeRemoteError = %q", got)
	}
}

func TestParseTunnelJobBindsProgramAndPID(t *testing.T) {
	t.Parallel()

	label := "com.warptweet.tunnel.db-1"
	job, err := parseTunnelJob(label, "{\n\tprogram = /Library/Application Support/WarpTweet/bin/warptweet\n\tpid = 4321\n}\n")
	if err != nil || !job.loaded || job.pid != 4321 {
		t.Fatalf("parseTunnelJob = %+v, %v", job, err)
	}
	for _, output := range []string{
		"program = /tmp/warptweet\npid = 4321\n",
		"program = /Library/Application Support/WarpTweet/bin/warptweet\npid = nope\n",
		"program = /Library/Application Support/WarpTweet/bin/warptweet\npid = 1\npid = 2\n",
		"pid = 4321\n",
	} {
		if _, err := parseTunnelJob(label, output); err == nil {
			t.Fatalf("accepted unbound launchd output %q", output)
		}
	}
}
