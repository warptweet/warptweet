package outcome

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"
)

func TestFromClassifiesContractCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		code string
		exit int
	}{
		{name: "help", err: flag.ErrHelp, code: CodeHelp, exit: 0},
		{name: "usage", err: errors.New("flag provided but not defined: -x"), code: CodeUsage, exit: 2},
		{name: "host busy sentinel", err: fmt.Errorf("%w: lock held", ErrHostBusy), code: CodeHostBusy, exit: 1},
		{name: "host busy", err: errors.New("host_busy: lock held"), code: CodeHostBusy, exit: 1},
		{name: "provisioner sentinel", err: fmt.Errorf("%w: missing socket", ErrProvisionerUnavailable), code: CodeProvisionerUnavailable, exit: 1},
		{name: "provisioner", err: errors.New("provisioner_unavailable: missing socket"), code: CodeProvisionerUnavailable, exit: 1},
		{name: "port", err: errors.New("listen port 15432 is reserved"), code: CodeLocalPortConflict, exit: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := From(test.err)
			if got.Code != test.code || got.ExitCode() != test.exit {
				t.Fatalf("code=%s exit=%d", got.Code, got.ExitCode())
			}
			if test.code != CodeHelp && !strings.Contains(got.Error(), test.err.Error()) && got.Code != CodeUsage {
				t.Fatalf("message=%q", got.Error())
			}
		})
	}
}

func TestNilErrorObjectAndEncode(t *testing.T) {
	t.Parallel()

	var raw *Error
	object := raw.Object()
	if object["ok"] != false {
		t.Fatalf("nil Object=%v", object)
	}
	encoded, err := Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"ok":false`) {
		t.Fatalf("Encode(nil)=%s", encoded)
	}
	if From(nil) != nil {
		t.Fatal("From(nil) must stay nil")
	}
}

func TestJSONObjectOmitsSecrets(t *testing.T) {
	t.Parallel()

	payload := New(CodeUsage, "host --stdout cannot be combined with --json", "Run warptweet host --help", 2).Object()
	raw, err := Encode(From(errors.New("host --stdout cannot be combined with --json")))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{`"invite"`, `"mac"`, `"nonce"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("json contains %s: %s", forbidden, text)
		}
	}
	if payload["ok"] != false {
		t.Fatalf("ok=%v", payload["ok"])
	}
}
