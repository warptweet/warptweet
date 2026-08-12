package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/installlayout"
)

func TestValidateEffectiveClientConfigAcceptsExactPolicy(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	path := writeEffectiveEngine(t, effectiveOutput(spec))
	if err := ValidateEffectiveClientConfig(context.Background(), path, spec); err != nil {
		t.Fatalf("ValidateEffectiveClientConfig: %v", err)
	}
}

func TestValidateManagedEffectiveClientConfigRequiresForegroundMaster(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	runtimeDirectory := filepath.Join(productionRuntimeRootForTest(), spec.TunnelID)
	controlPath := filepath.Join(runtimeDirectory, controlSocketName)
	path := writeEffectiveEngine(t, managedEffectiveOutput(spec, controlPath))
	if err := ValidateManagedEffectiveClientConfig(
		context.Background(),
		path,
		runtimeDirectory,
		spec,
	); err != nil {
		t.Fatalf("ValidateManagedEffectiveClientConfig: %v", err)
	}
}

func TestValidateManagedEffectiveClientConfigRejectsWrongMasterPIDBoundary(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	runtimeDirectory := filepath.Join(productionRuntimeRootForTest(), spec.TunnelID)
	controlPath := filepath.Join(runtimeDirectory, controlSocketName)
	valid := managedEffectiveOutput(spec, controlPath)
	for name, output := range map[string]string{
		"master disabled": strings.Replace(valid, "controlmaster true\n", "controlmaster false\n", 1),
		"fork enabled":    strings.Replace(valid, "forkafterauthentication no\n", "forkafterauthentication yes\n", 1),
		"wrong path":      strings.Replace(valid, "controlpath "+controlPath+"\n", "controlpath /tmp/foreign\n", 1),
		"persistent mux":  strings.Replace(valid, "controlpersist no\n", "controlpersist 60\n", 1),
	} {
		name, output := name, output
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := writeEffectiveEngine(t, output)
			if err := ValidateManagedEffectiveClientConfig(
				context.Background(), path, runtimeDirectory, spec,
			); err == nil {
				t.Fatal("managed effective validation accepted a weakened PID boundary")
			}
		})
	}
}

func TestValidateEffectiveClientConfigUsesExactClosedArguments(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	path := writeEffectiveEngine(t, effectiveOutput(spec))
	if err := ValidateEffectiveClientConfig(context.Background(), path, spec); err != nil {
		t.Fatalf("ValidateEffectiveClientConfig: %v", err)
	}
	gotBytes, err := os.ReadFile(path + ".args")
	if err != nil {
		t.Fatalf("read recorded arguments: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(string(gotBytes), "\n"), "\n")
	closed, err := Arguments(spec)
	if err != nil {
		t.Fatalf("Arguments: %v", err)
	}
	want := append([]string{"-G"}, closed...)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("effective arguments = %q, want %q", got, want)
	}
}

func TestValidateEffectiveClientConfigRejectsResolvedFallback(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	output := strings.Replace(effectiveOutput(spec),
		"kexalgorithms "+spec.Profile.KeyExchangeAlgorithm,
		"kexalgorithms "+spec.Profile.KeyExchangeAlgorithm+",curve25519-sha256",
		1,
	)
	path := writeEffectiveEngine(t, output)
	if err := ValidateEffectiveClientConfig(context.Background(), path, spec); err == nil {
		t.Fatal("effective configuration accepted a classical fallback")
	}
}

func TestValidateEffectiveClientConfigAcceptsCompiledOutGSSAPI(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	output := strings.Replace(effectiveOutput(spec), "gssapiauthentication no\n", "", 1)
	path := writeEffectiveEngine(t, output)
	if err := ValidateEffectiveClientConfig(context.Background(), path, spec); err != nil {
		t.Fatalf("ValidateEffectiveClientConfig: %v", err)
	}
}

func TestValidateEffectiveClientConfigRejectsParserDiagnostics(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	path := filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\ncat <<'OUTPUT'\n" + effectiveOutput(spec) +
		"OUTPUT\necho 'unsupported security option' >&2\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ValidateEffectiveClientConfig(context.Background(), path, spec); err == nil {
		t.Fatal("effective configuration accepted parser diagnostics")
	}
}

func TestValidateEffectiveClientConfigRejectsForwardingExpansion(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	valid := effectiveOutput(spec)
	tests := []struct {
		name   string
		output string
	}{
		{
			name: "second local forward",
			output: valid +
				"localforward [127.0.0.1]:18080 [198.51.100.20]:80\n",
		},
		{
			name: "wrong local listener",
			output: strings.Replace(
				valid,
				effectiveLocalForward(spec),
				"[127.0.0.1]:15433 [10.0.0.10]:5432",
				1,
			),
		},
		{
			name: "wrong local target",
			output: strings.Replace(
				valid,
				effectiveLocalForward(spec),
				"[127.0.0.1]:15432 [10.0.0.11]:5432",
				1,
			),
		},
		{
			name:   "remote forward",
			output: valid + "remoteforward [127.0.0.1]:18080 [198.51.100.20]:80\n",
		},
		{
			name:   "dynamic forward",
			output: valid + "dynamicforward [127.0.0.1]:1080\n",
		},
		{
			name:   "TUN forward",
			output: strings.Replace(valid, "tunnel false\n", "tunnel point-to-point\n", 1),
		},
		{
			name:   "TUN device",
			output: strings.Replace(valid, "tunneldevice any:any\n", "tunneldevice 0:0\n", 1),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := writeEffectiveEngine(t, test.output)
			if err := ValidateEffectiveClientConfig(
				context.Background(),
				path,
				spec,
			); err == nil {
				t.Fatal("effective configuration accepted expanded forwarding")
			}
		})
	}
}

func effectiveOutput(spec ClientSpec) string {
	return fmt.Sprintf(`hostname %s
port %d
user %s
hostkeyalias warptweet-%s
kexalgorithms %s
hostkeyalgorithms %s
pubkeyacceptedalgorithms %s
ciphers %s
identityfile %s
userknownhostsfile %s
globalknownhostsfile %s
compression no
batchmode yes
preferredauthentications publickey
pubkeyauthentication true
passwordauthentication no
kbdinteractiveauthentication no
gssapiauthentication no
hostbasedauthentication no
identitiesonly yes
identityagent none
stricthostkeychecking true
checkhostip no
verifyhostkeydns false
updatehostkeys false
hashknownhosts no
forwardagent no
forwardx11 no
gatewayports no
requesttty false
sessiontype none
stdinnull yes
controlmaster false
controlpersist no
forkafterauthentication no
exitonforwardfailure yes
clearallforwardings no
permitlocalcommand no
enableescapecommandline no
proxyusefdpass no
addkeystoagent false
canonicalizehostname false
connectionattempts 1
connecttimeout 15
serveraliveinterval 15
serveralivecountmax 3
tcpkeepalive no
rekeylimit 536870912 3600
loglevel VERBOSE
escapechar none
localforward %s
tunnel false
tunneldevice any:any
`,
		spec.ServerAddress,
		spec.ServerPort,
		spec.ServerUser,
		spec.TunnelID,
		spec.Profile.KeyExchangeAlgorithm,
		spec.Profile.AuthenticationKeyType,
		spec.Profile.AuthenticationKeyType,
		strings.Join(spec.Profile.Ciphers, ","),
		spec.IdentityFile,
		spec.KnownHostsFile,
		spec.GlobalKnownHostsFile,
		effectiveLocalForward(spec),
	)
}

func managedEffectiveOutput(spec ClientSpec, controlPath string) string {
	output := effectiveOutput(spec)
	output = strings.Replace(output, "controlmaster false\n", "controlmaster true\n", 1)
	return strings.Replace(output, "controlpersist no\n", "controlpath "+controlPath+"\ncontrolpersist no\n", 1)
}

func writeEffectiveEngine(t *testing.T, output string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\ncat <<'OUTPUT'\n" + output + "OUTPUT\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func productionRuntimeRootForTest() string {
	if selected, err := artifactprofile.Current(); err == nil && selected.Layout.ClientRuntimeRoot != "" {
		return selected.Layout.ClientRuntimeRoot
	}
	return installlayout.ClientRuntimeRoot
}
