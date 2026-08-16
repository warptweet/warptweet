package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/profile"
)

func TestRenderAuthorizedKeyAddsExactManagedRestrictions(t *testing.T) {
	t.Parallel()

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	blob := authorizedKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	input := selectedProfile.AuthenticationKeyType + " " + blob + " discarded input comment\n"

	got, err := RenderAuthorizedKey(validConfig(), []byte(input))
	if err != nil {
		t.Fatalf("RenderAuthorizedKey: %v", err)
	}
	want := "restrict,port-forwarding,permitopen=\"198.51.100.7:5432\" " +
		selectedProfile.AuthenticationKeyType + " " + blob + " " + ManagedClientMarker + "\n"
	if string(got) != want {
		t.Fatalf("unexpected authorized key:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	if strings.Contains(string(got), "discarded input comment") {
		t.Fatal("RenderAuthorizedKey retained the untrusted input comment")
	}

	withoutComment, err := RenderAuthorizedKey(
		validConfig(),
		[]byte(selectedProfile.AuthenticationKeyType+" "+blob),
	)
	if err != nil {
		t.Fatalf("RenderAuthorizedKey without comment: %v", err)
	}
	if !bytes.Equal(got, withoutComment) {
		t.Fatal("input comments changed deterministic output")
	}
	report, err := ValidateAuthorizedKeys(validConfig(), got)
	if err != nil {
		t.Fatalf("ValidateAuthorizedKeys(RenderAuthorizedKey(...)): %v", err)
	}
	if report.KeyCount != 1 {
		t.Fatalf("AuthorizedKeysReport.KeyCount = %d, want 1", report.KeyCount)
	}
}

func TestRenderAuthorizedKeyFormatsIPv6PermitOpen(t *testing.T) {
	t.Parallel()

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	blob := authorizedKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	config := validConfig()
	config.Target = Endpoint{Address: netip.MustParseAddr("2001:db8::20"), Port: 443}

	got, err := RenderAuthorizedKey(
		config,
		[]byte(selectedProfile.AuthenticationKeyType+" "+blob+"\r\n"),
	)
	if err != nil {
		t.Fatalf("RenderAuthorizedKey: %v", err)
	}
	if !strings.HasPrefix(
		string(got),
		"restrict,port-forwarding,permitopen=\"[2001:db8::20]:443\" ",
	) {
		t.Fatalf("authorized key has wrong IPv6 restriction: %s", got)
	}
}

func TestRenderAuthorizedKeyRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	config := validConfig()
	config.Target.Port = 0
	input := selectedProfile.AuthenticationKeyType + " " + authorizedKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)

	_, err = RenderAuthorizedKey(config, []byte(input))
	if err == nil {
		t.Fatal("RenderAuthorizedKey accepted an invalid server policy")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error does not wrap ErrInvalidConfig: %v", err)
	}
}

func TestRenderAuthorizedKeyRejectsUnsafeKeyInput(t *testing.T) {
	t.Parallel()

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	validBlob := authorizedKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	validLine := selectedProfile.AuthenticationKeyType + " " + validBlob

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: nil},
		{name: "oversized", input: bytes.Repeat([]byte{'a'}, MaxAuthorizedKeyInputBytes+1)},
		{name: "missing blob", input: []byte(selectedProfile.AuthenticationKeyType)},
		{name: "leading whitespace", input: []byte(" " + validLine)},
		{name: "trailing whitespace", input: []byte(validLine + " ")},
		{name: "extra public-key line", input: []byte(validLine + "\n" + validLine)},
		{name: "trailing blank line", input: []byte(validLine + "\n\n")},
		{name: "extra comment line", input: []byte(validLine + "\n# comment")},
		{name: "embedded carriage return", input: []byte(validLine + "\rcomment")},
		{name: "embedded control character", input: []byte(validLine + " comment\x00")},
		{
			name:  "preexisting restrictions",
			input: []byte("restrict,port-forwarding " + validLine),
		},
		{
			name:  "preexisting command option",
			input: []byte("command=\"false\" " + validLine),
		},
		{name: "wrong outer algorithm", input: []byte("ssh-ed25519 " + validBlob)},
		{name: "certificate outer algorithm", input: []byte("ssh-mldsa44-ed25519-cert-v01@openssh.com " + validBlob)},
		{name: "invalid base64", input: []byte(selectedProfile.AuthenticationKeyType + " ***")},
		{
			name: "wrong inner algorithm",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + authorizedKeyBlob(
				"ssh-ed25519",
				selectedProfile.RawPublicKeyBytes,
				nil,
			)),
		},
		{
			name: "short raw public key",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + authorizedKeyBlob(
				selectedProfile.AuthenticationKeyType,
				selectedProfile.RawPublicKeyBytes-1,
				nil,
			)),
		},
		{
			name: "long raw public key",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + authorizedKeyBlob(
				selectedProfile.AuthenticationKeyType,
				selectedProfile.RawPublicKeyBytes+1,
				nil,
			)),
		},
		{
			name: "trailing blob bytes",
			input: []byte(selectedProfile.AuthenticationKeyType + " " + authorizedKeyBlob(
				selectedProfile.AuthenticationKeyType,
				selectedProfile.RawPublicKeyBytes,
				[]byte{1},
			)),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := RenderAuthorizedKey(validConfig(), test.input)
			if err == nil {
				t.Fatal("RenderAuthorizedKey accepted unsafe input")
			}
			if !errors.Is(err, ErrInvalidAuthorizedKey) {
				t.Fatalf("error does not wrap ErrInvalidAuthorizedKey: %v", err)
			}
		})
	}
}

func TestValidateAuthorizedKeysRejectsNoncanonicalOrUnsafeInput(t *testing.T) {
	t.Parallel()

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("profile.Lookup: %v", err)
	}
	validBlob := authorizedKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	valid, err := RenderAuthorizedKey(
		validConfig(),
		[]byte(selectedProfile.AuthenticationKeyType+" "+validBlob),
	)
	if err != nil {
		t.Fatalf("RenderAuthorizedKey: %v", err)
	}
	wrongInnerBlob := authorizedKeyBlob(
		"ssh-ed25519",
		selectedProfile.RawPublicKeyBytes,
		nil,
	)
	shortBlob := authorizedKeyBlob(
		selectedProfile.AuthenticationKeyType,
		selectedProfile.RawPublicKeyBytes-1,
		nil,
	)
	validText := string(valid)

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "oversized", input: bytes.Repeat([]byte{'a'}, MaxAuthorizedKeysBytes+1)},
		{name: "missing terminal LF", input: bytes.TrimSuffix(valid, []byte{'\n'})},
		{
			name: "CRLF",
			input: append(
				append([]byte(nil), bytes.TrimSuffix(valid, []byte{'\n'})...),
				'\r',
				'\n',
			),
		},
		{name: "trailing blank line", input: append(append([]byte(nil), valid...), '\n')},
		{name: "duplicate key", input: append(append([]byte(nil), valid...), valid...)},
		{name: "comment line", input: append([]byte("# comment\n"), valid...)},
		{
			name: "reordered options",
			input: []byte(strings.Replace(
				validText,
				"restrict,port-forwarding,permitopen=",
				"port-forwarding,restrict,permitopen=",
				1,
			)),
		},
		{
			name:  "missing restrict",
			input: []byte(strings.Replace(validText, "restrict,", "", 1)),
		},
		{
			name:  "wrong target",
			input: []byte(strings.Replace(validText, "198.51.100.7:5432", "198.51.100.8:5432", 1)),
		},
		{
			name: "wrong outer algorithm",
			input: []byte(strings.Replace(
				validText,
				selectedProfile.AuthenticationKeyType+" ",
				"ssh-ed25519 ",
				1,
			)),
		},
		{
			name:  "invalid base64",
			input: []byte(strings.Replace(validText, validBlob, "***", 1)),
		},
		{
			name:  "wrong inner algorithm",
			input: []byte(strings.Replace(validText, validBlob, wrongInnerBlob, 1)),
		},
		{
			name:  "short raw key",
			input: []byte(strings.Replace(validText, validBlob, shortBlob, 1)),
		},
		{
			name:  "wrong marker",
			input: []byte(strings.Replace(validText, ManagedClientMarker, "operator-comment", 1)),
		},
		{
			name: "additional comment",
			input: []byte(strings.Replace(
				validText,
				ManagedClientMarker+"\n",
				ManagedClientMarker+" extra\n",
				1,
			)),
		},
		{
			name:  "extra separator",
			input: []byte(strings.Replace(validText, " "+validBlob, "  "+validBlob, 1)),
		},
		{
			name:  "tab separator",
			input: []byte(strings.Replace(validText, " "+validBlob, "\t"+validBlob, 1)),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			report, err := ValidateAuthorizedKeys(validConfig(), test.input)
			if err == nil {
				t.Fatalf("ValidateAuthorizedKeys accepted unsafe input and returned %#v", report)
			}
			if !errors.Is(err, ErrInvalidAuthorizedKey) {
				t.Fatalf("error does not wrap ErrInvalidAuthorizedKey: %v", err)
			}
		})
	}
}

func TestValidateAuthorizedKeysAcceptsEmptyAndMultipleDistinctClients(t *testing.T) {
	t.Parallel()

	config := validConfig()
	empty, err := ValidateAuthorizedKeys(config, nil)
	if err != nil || empty.KeyCount != 0 {
		t.Fatalf("empty pre-enrollment state: report=%+v err=%v", empty, err)
	}
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatal(err)
	}
	firstBlob := authorizedKeyBlob(selected.AuthenticationKeyType, selected.RawPublicKeyBytes, nil)
	secondRaw, err := base64.StdEncoding.DecodeString(firstBlob)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw[len(secondRaw)-1] = 1
	secondBlob := base64.StdEncoding.EncodeToString(secondRaw)
	first, err := RenderAuthorizedKey(config, []byte(selected.AuthenticationKeyType+" "+firstBlob))
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderAuthorizedKey(config, []byte(selected.AuthenticationKeyType+" "+secondBlob))
	if err != nil {
		t.Fatal(err)
	}
	report, err := ValidateAuthorizedKeys(config, append(first, second...))
	if err != nil || report.KeyCount != 2 {
		t.Fatalf("multiple clients: report=%+v err=%v", report, err)
	}
}

func TestValidateAuthorizedKeysRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	config := validConfig()
	config.SSHDBinarySHA256 = ""
	_, err := ValidateAuthorizedKeys(config, []byte("ignored\n"))
	if err == nil {
		t.Fatal("ValidateAuthorizedKeys accepted invalid server policy")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error does not wrap ErrInvalidConfig: %v", err)
	}
}

func authorizedKeyBlob(algorithm string, rawSize int, trailing []byte) string {
	name := []byte(algorithm)
	blob := make([]byte, 4+len(name)+4+rawSize+len(trailing))
	binary.BigEndian.PutUint32(blob[:4], uint32(len(name)))
	copy(blob[4:], name)
	offset := 4 + len(name)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(rawSize))
	for index := 0; index < rawSize; index++ {
		blob[offset+4+index] = byte(index)
	}
	copy(blob[offset+4+rawSize:], trailing)
	return base64.StdEncoding.EncodeToString(blob)
}
