package command

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/enrollment"
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
			if stdout.Len() != 0 {
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
	if code != 2 || !strings.Contains(stderr.String(), `unknown command "gateway"`) {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
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
		once       bool
		wantEnroll []string
		wantUp     []string
	}{
		{
			name:       "no flags",
			wantEnroll: []string{"invite.wtinvite"},
			wantUp:     []string{"tunnel-1"},
		},
		{
			name:       "yes true",
			yes:        true,
			wantEnroll: []string{"--yes", "invite.wtinvite"},
			wantUp:     []string{"tunnel-1"},
		},
		{
			name:       "yes false",
			yes:        false,
			wantEnroll: []string{"invite.wtinvite"},
			wantUp:     []string{"tunnel-1"},
		},
		{
			name:       "once true",
			once:       true,
			wantEnroll: []string{"invite.wtinvite"},
			wantUp:     []string{"--once", "tunnel-1"},
		},
		{
			name:       "once false",
			once:       false,
			wantEnroll: []string{"invite.wtinvite"},
			wantUp:     []string{"tunnel-1"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gotEnroll := buildConnectEnrollArgs("invite.wtinvite", test.yes, "")
			if !reflect.DeepEqual(gotEnroll, test.wantEnroll) {
				t.Fatalf("enroll args=%v want=%v", gotEnroll, test.wantEnroll)
			}
			gotUp := buildConnectUpArgs("tunnel-1", test.once)
			if !reflect.DeepEqual(gotUp, test.wantUp) {
				t.Fatalf("up args=%v want=%v", gotUp, test.wantUp)
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
