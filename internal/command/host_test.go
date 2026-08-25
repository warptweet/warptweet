package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/server"
)

func TestUsageMentionsHostAndConnect(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, required := range []string{
		"warptweet host --to",
		"warptweet connect <invite.wtinvite>",
	} {
		if !strings.Contains(stdout.String(), required) {
			t.Fatalf("usage omits %q: %s", required, stdout.String())
		}
	}
}

func TestHostHumanOutputClassifiesInviteAsConfidentialBearer(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := writeHostHuman(&stdout, hostHumanOutput{
		Target:     "127.0.0.1:5432",
		Listen:     "0.0.0.0:2222",
		InvitePath: "/tmp/laptop.wtinvite",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "confidential bearer") {
		t.Fatalf("host output missing classification: %s", stdout.String())
	}
	for _, state := range []string{"local_listener_ready", "published_endpoint_configured", "external_reachability_unverified"} {
		if !strings.Contains(stdout.String(), state) {
			t.Fatalf("host output missing %s: %s", state, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "host ready") {
		t.Fatalf("host output still prints a single host ready: %s", stdout.String())
	}
}

func TestHostHumanOutputNamesResumedOutstandingInvite(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := writeHostHuman(&stdout, hostHumanOutput{
		Target:        "127.0.0.1:5432",
		Listen:        "10.168.0.2:2222",
		InvitePath:    "/tmp/laptop.wtinvite",
		InviteID:      "abc123",
		ClientName:    "laptop-1",
		InviteResumed: true,
	}); err != nil {
		t.Fatal(err)
	}
	text := stdout.String()
	for _, required := range []string{
		"resumed unused issued invite abc123 (laptop-1)",
		"one outstanding invite per published_endpoint_generation",
		"/tmp/laptop.wtinvite",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %q in %s", required, text)
		}
	}
}

func TestParseHostTargetPortSugar(t *testing.T) {
	t.Parallel()

	endpoint, err := parseHostTarget("5432")
	if err != nil {
		t.Fatalf("parseHostTarget: %v", err)
	}
	if endpoint.String() != "127.0.0.1:5432" {
		t.Fatalf("endpoint=%s", endpoint)
	}
	endpoint, err = parseHostTarget("198.51.100.20:5432")
	if err != nil {
		t.Fatalf("parseHostTarget ip: %v", err)
	}
	if endpoint.String() != "198.51.100.20:5432" {
		t.Fatalf("endpoint=%s", endpoint)
	}
	if _, err := parseHostTarget("0"); err == nil {
		t.Fatal("accepted zero port")
	}
	if _, err := parseHostTarget("hostname:22"); err == nil {
		t.Fatal("accepted hostname")
	}
}

func TestHostFailsClosedOnNonLinux(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "linux" {
		t.Skip("public host is supported on Linux")
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"host", "--to", "5432", "--no-invite"}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("host accepted a non-Linux GOOS")
	}
	if !strings.Contains(stderr.String(), "Linux") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestResolveListenKeepsStoredBindWithoutDiscovery(t *testing.T) {
	t.Parallel()

	stored := server.Config{
		Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722),
	}
	discovered := false
	got, err := resolveListen("", &stored, func() (netip.Addr, error) {
		discovered = true
		return netip.MustParseAddr("192.0.2.99"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if discovered {
		t.Fatal("omitted --listen re-ran inspect-network despite stored bind")
	}
	if got.String() != "10.168.0.2:2222" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveListenFlagOverridesStoredBind(t *testing.T) {
	t.Parallel()

	stored := server.Config{
		Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722),
	}
	got, err := resolveListen("192.0.2.10:2222", &stored, func() (netip.Addr, error) {
		t.Fatal("discover called")
		return netip.Addr{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "192.0.2.10:2222" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveListenFallsBackToLoopbackWhenDiscoveryIsEmpty(t *testing.T) {
	t.Parallel()

	got, err := resolveListen("", nil, func() (netip.Addr, error) {
		return netip.Addr{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "127.0.0.1:2222" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveListenPropagatesDiscoveryError(t *testing.T) {
	t.Parallel()

	want := errors.New("inspect-network: no route")
	if _, err := resolveListen("", nil, func() (netip.Addr, error) {
		return netip.Addr{}, want
	}); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestPublicationChangeBlockedByLiveInventory(t *testing.T) {
	t.Parallel()

	err := publicationChangeBlocked([]enrollment.ClientRecord{{
		ClientID: "client-1",
		Status:   enrollment.ClientStatusActive,
	}}, nil)
	if err == nil || !strings.Contains(err.Error(), "client-1") {
		t.Fatalf("error = %v", err)
	}
	err = publicationChangeBlocked(nil, []enrollment.Record{{
		Invite: enrollment.Invite{InviteID: "invite-1"},
		Status: enrollment.StatusIssued,
	}})
	if err == nil || !strings.Contains(err.Error(), "invite-1") {
		t.Fatalf("error = %v", err)
	}
	if err := publicationChangeBlocked([]enrollment.ClientRecord{{
		ClientID: "expired",
		Status:   enrollment.ClientStatusExpired,
	}}, []enrollment.Record{{
		Invite: enrollment.Invite{InviteID: "used"},
		Status: enrollment.StatusConsumed,
	}}); err != nil {
		t.Fatalf("terminal inventory blocked: %v", err)
	}
}

func TestHostRequiresTo(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"host"}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("host accepted missing --to")
	}
	if !strings.Contains(stderr.String(), "--to") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestHostRejectsMutuallyExclusiveFlags(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "stdout with no-invite",
			args: []string{"host", "--to", "5432", "--stdout", "--no-invite"},
			want: "host --stdout cannot be combined with --no-invite",
		},
		{
			name: "stdout with json",
			args: []string{"host", "--to", "5432", "--stdout", "--json"},
			want: "host --stdout cannot be combined with --json",
		},
		{
			name: "stdout with out",
			args: []string{"host", "--to", "5432", "--stdout", "--out", "invite.wtinvite"},
			want: "host --stdout cannot be combined with --out",
		},
		{
			name: "no-invite with out",
			args: []string{"host", "--to", "5432", "--no-invite", "--out", "invite.wtinvite"},
			want: "host --no-invite cannot be combined with invite naming flags",
		},
		{
			name: "no-invite with name",
			args: []string{"host", "--to", "5432", "--no-invite", "--name", "laptop"},
			want: "host --no-invite cannot be combined with invite naming flags",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), testCase.args, nil, &stdout, &stderr)
			if code == 0 || !strings.Contains(stderr.String(), testCase.want) {
				t.Fatalf("code=%d stderr=%s want %q", code, stderr.String(), testCase.want)
			}
			if strings.Contains(strings.Join(testCase.args, " "), "--json") {
				if !strings.Contains(stdout.String(), `"code":"usage"`) {
					t.Fatalf("json stdout=%s", stdout.String())
				}
			} else if stdout.Len() != 0 {
				t.Fatalf("stdout=%s, want empty before filesystem work", stdout.String())
			}
		})
	}
}

func TestHostRejectsAccessForAboveMaximum(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"host", "--to", "5432", "--access-for", "400d"}, nil, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "exceeds host maximum") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestHostRejectsTTLFlag(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"host", "--to", "5432", "--ttl", "30d"}, nil, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestHostRejectsEnrollmentReadinessBypass(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"host", "--to", "5432", "--no-enroll-listen"}, nil, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestLegacyGatewayCommandIsRejected(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"gateway", "--to", "5432"}, nil, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "gateway was replaced by") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestReplacementCommandsEmitOneJSONObject(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"gateway", "--json"},
		{"server", "init", "--json"},
		{"server", "invite", "--json"},
	}
	for _, args := range cases {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run(context.Background(), args, nil, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%v code=%d stderr=%s", args, code, stderr.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
			t.Fatalf("%v decode %q: %v", args, stdout.String(), err)
		}
		if payload["ok"] != false {
			t.Fatalf("%v payload=%v", args, payload)
		}
		errorObject, _ := payload["error"].(map[string]any)
		if errorObject["replacement"] == nil || errorObject["code"] != "usage" {
			t.Fatalf("%v error=%v", args, errorObject)
		}
	}
}

func TestConnectRequiresInvitePath(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"connect"}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("connect accepted missing invite")
	}
	if !strings.Contains(stderr.String(), "invite") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestParseEnrollConnectFields(t *testing.T) {
	t.Parallel()

	tunnelID, listen, service, err := parseEnrollConnectFields(`{
  "status":"enrolled",
  "tunnel_id":"studio-mac",
  "listen_endpoint":"127.0.0.1:15432",
  "service_endpoint":"127.0.0.1:5432"
}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tunnelID != "studio-mac" || listen != "127.0.0.1:15432" || service != "127.0.0.1:5432" {
		t.Fatalf("fields=%s %s %s", tunnelID, listen, service)
	}
	_, _, service, err = parseEnrollConnectFields(`{
  "tunnel_id":"studio-mac",
  "listen_endpoint":"127.0.0.1:15432"
}`)
	if err != nil {
		t.Fatalf("parse without service: %v", err)
	}
	if service != "" {
		t.Fatalf("service=%q", service)
	}
}

func TestBuildConnectArgs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		yes        bool
		listenPort uint16
		wantEnroll []string
	}{
		{
			name:       "no flags",
			wantEnroll: []string{"--restart", "unless-stopped", "invite.wtinvite"},
		},
		{
			name:       "yes true",
			yes:        true,
			listenPort: 15432,
			wantEnroll: []string{"--listen-port", "15432", "--restart", "unless-stopped", "--yes", "invite.wtinvite"},
		},
		{
			name:       "yes false",
			yes:        false,
			listenPort: 15432,
			wantEnroll: []string{"--listen-port", "15432", "--restart", "unless-stopped", "invite.wtinvite"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gotEnroll := buildConnectEnrollArgs("invite.wtinvite", test.yes, "", test.listenPort, "unless-stopped")
			if !reflect.DeepEqual(gotEnroll, test.wantEnroll) {
				t.Fatalf("enroll args=%v want=%v", gotEnroll, test.wantEnroll)
			}
		})
	}
}

func TestHostInviteFileNamingHelpersMatchProductPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path, err := enrollment.WriteInviteFile(dir, "Studio Mac", "a81f0000000000000000000000000001", []byte("{}\n"))
	if err != nil {
		t.Fatalf("WriteInviteFile: %v", err)
	}
	if filepath.Base(path) != "studio-mac.wtinvite" {
		t.Fatalf("basename=%s", filepath.Base(path))
	}
	if _, err := enrollment.WriteInviteFileExact(path, []byte("{}\n")); !errors.Is(err, enrollment.ErrInvitePathCollision) {
		t.Fatalf("exact overwrite err=%v", err)
	}
}

func TestEnsureDirectoryModeRepairsExistingMode(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	hostKeyDir := filepath.Join(root, "ssh")
	keysDir := filepath.Join(root, "authorized_keys")
	if err := os.Mkdir(hostKeyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectoryMode(hostKeyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectoryMode(keysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hostInfo, err := os.Stat(hostKeyDir)
	if err != nil {
		t.Fatal(err)
	}
	if hostInfo.Mode().Perm() != 0o700 {
		t.Fatalf("host key dir mode=%o", hostInfo.Mode().Perm())
	}
	keysInfo, err := os.Stat(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	if keysInfo.Mode().Perm() != 0o755 {
		t.Fatalf("authorized_keys dir mode=%o", keysInfo.Mode().Perm())
	}
}

func TestEnsureDirectoryModeSetsSetgid(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "clients")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectoryMode(path, 0o2750); err != nil {
		t.Fatal(err)
	}
	stripped, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stripped.Mode()&os.ModeSetgid != 0 {
		t.Fatal("unix 0o2750 must not be treated as Go setgid")
	}
	if err := ensureDirectoryMode(path, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("clients dir missing setgid: %s", info.Mode())
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("clients dir mode=%o", info.Mode().Perm())
	}
}
