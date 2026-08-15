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

func TestUsageMentionsGatewayAndConnect(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, required := range []string{
		"warptweet gateway --to",
		"warptweet connect <invite.wtinvite>",
	} {
		if !strings.Contains(stdout.String(), required) {
			t.Fatalf("usage omits %q: %s", required, stdout.String())
		}
	}
}

func TestParseGatewayTargetPortSugar(t *testing.T) {
	t.Parallel()

	endpoint, err := parseGatewayTarget("5432")
	if err != nil {
		t.Fatalf("parseGatewayTarget: %v", err)
	}
	if endpoint.String() != "127.0.0.1:5432" {
		t.Fatalf("endpoint=%s", endpoint)
	}
	endpoint, err = parseGatewayTarget("198.51.100.20:5432")
	if err != nil {
		t.Fatalf("parseGatewayTarget ip: %v", err)
	}
	if endpoint.String() != "198.51.100.20:5432" {
		t.Fatalf("endpoint=%s", endpoint)
	}
	if _, err := parseGatewayTarget("0"); err == nil {
		t.Fatal("accepted zero port")
	}
	if _, err := parseGatewayTarget("hostname:22"); err == nil {
		t.Fatal("accepted hostname")
	}
}

func TestGatewayRequiresTo(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"gateway"}, nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("gateway accepted missing --to")
	}
	if !strings.Contains(stderr.String(), "--to") {
		t.Fatalf("stderr=%s", stderr.String())
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
		name string
		yes  bool
		once bool
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

func TestGatewayInviteFileNamingHelpersMatchProductPolicy(t *testing.T) {
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
