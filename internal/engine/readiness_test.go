package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/installlayout"
)

func TestManagedClientPolicyUsesFixedPrivateControlPath(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	runtimeDirectory := filepath.Join(installlayout.ClientRuntimeRoot, spec.TunnelID)
	policy, err := managedClientPolicyAtRoot(runtimeDirectory, spec, installlayout.ClientRuntimeRoot)
	if err != nil {
		t.Fatalf("managedClientPolicyAtRoot: %v", err)
	}
	arguments := clientPolicyArguments(policy)
	joined := strings.Join(arguments, "\x00")
	for _, required := range []string{
		"-F\x00none",
		`ControlMaster=yes`,
		`ControlPath=` + filepath.Join(runtimeDirectory, controlSocketName),
		`ControlPersist=no`,
		`ForkAfterAuthentication=no`,
		`SessionType=none`,
		`LocalForward=[127.0.0.1]:15432 [10.0.0.10]:5432`,
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("managed arguments do not contain %q: %q", required, arguments)
		}
	}
	if strings.Contains(joined, "-S") || strings.Contains(joined, "-M") ||
		strings.Contains(joined, "-L") || strings.Contains(joined, "-N") {
		t.Fatalf("managed arguments bypass the ordered option policy: %q", arguments)
	}
}

func TestManagedClientPolicyRejectsCallerSelectedRuntimePath(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	for _, runtimeDirectory := range []string{
		"/tmp/warptweet/" + spec.TunnelID,
		filepath.Join(installlayout.ClientRuntimeRoot, "another-tunnel"),
		filepath.Join(installlayout.ClientRuntimeRoot, spec.TunnelID, "nested"),
	} {
		if _, err := managedClientPolicyAtRoot(runtimeDirectory, spec, installlayout.ClientRuntimeRoot); err == nil {
			t.Errorf("managedClientPolicyAtRoot accepted %q", runtimeDirectory)
		}
	}
}

func TestValidateControlPathIncludesOpenSSHTemporarySuffixBudget(t *testing.T) {
	t.Parallel()

	maximumBase := "/" + strings.Repeat("a", unixSocketMaximumPathBytes-controlSocketTemporarySuffixBytes-1)
	if got := len(maximumBase); got != 90 {
		t.Fatalf("test control path length = %d, want 90", got)
	}
	if err := validateControlPath(maximumBase); err != nil {
		t.Fatalf("validateControlPath at exact budget: %v", err)
	}
	if err := validateControlPath(maximumBase + "b"); err == nil {
		t.Fatal("validateControlPath accepted a path whose temporary socket exceeds sun_path")
	}
}

func TestMaximumTunnelIDFitsFixedControlSocketBudget(t *testing.T) {
	t.Parallel()

	spec := validClientSpec(t)
	spec.TunnelID = strings.Repeat("a", 64)
	runtimeDirectory := filepath.Join(installlayout.ClientRuntimeRoot, spec.TunnelID)
	controlPath := filepath.Join(runtimeDirectory, controlSocketName)
	if got := len(controlPath); got != 89 {
		t.Fatalf("maximum fixed control path length = %d, want 89", got)
	}
	if got := len(controlPath) + controlSocketTemporarySuffixBytes; got != 106 {
		t.Fatalf("maximum temporary control path length = %d, want 106", got)
	}
	if _, err := managedClientPolicyAtRoot(runtimeDirectory, spec, installlayout.ClientRuntimeRoot); err != nil {
		t.Fatalf("managedClientPolicyAtRoot at maximum tunnel ID: %v", err)
	}

	darwinRuntimeDirectory := filepath.Join(installlayout.DarwinClientRuntimeRoot, spec.TunnelID)
	darwinControlPath := filepath.Join(darwinRuntimeDirectory, controlSocketName)
	if got := len(darwinControlPath) + controlSocketTemporarySuffixBytes; got > unixSocketMaximumPathBytes {
		t.Fatalf("darwin temporary control path length = %d, exceeds %d", got, unixSocketMaximumPathBytes)
	}
	if _, err := managedClientPolicyAtRoot(darwinRuntimeDirectory, spec, installlayout.DarwinClientRuntimeRoot); err != nil {
		t.Fatalf("managedClientPolicyAtRoot for darwin runtime: %v", err)
	}
}

func TestParseControlCheckOutputRequiresExactPinnedStderr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output readinessCommandOutput
		valid  bool
	}{
		{name: "exact", output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\r\n")}, valid: true},
		{name: "stdout", output: readinessCommandOutput{stdout: []byte("Master running (pid=4321)\r\n")}},
		{name: "LF only", output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\n")}},
		{name: "leading zero", output: readinessCommandOutput{stderr: []byte("Master running (pid=04321)\r\n")}},
		{name: "negative", output: readinessCommandOutput{stderr: []byte("Master running (pid=-1)\r\n")}},
		{name: "suffix", output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\r\nextra")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pid, err := parseControlCheckOutput(test.output)
			if test.valid {
				if err != nil || pid != 4321 {
					t.Fatalf("parseControlCheckOutput = (%d, %v), want (4321, nil)", pid, err)
				}
			} else if err == nil {
				t.Fatalf("parseControlCheckOutput accepted %#v", test.output)
			}
		})
	}
}

func TestControlCheckArgumentsDisableAmbientConfiguration(t *testing.T) {
	t.Parallel()

	path := "/run/warptweet/tunnels/database-primary/c"
	want := []string{
		"-F", "none",
		"-q",
		"-o", `BatchMode=yes`,
		"-o", `ControlMaster=no`,
		"-o", `ControlPath=/run/warptweet/tunnels/database-primary/c`,
		"-o", `ControlPersist=no`,
		"-O", "check",
		hostAlias,
	}
	if got := controlCheckArguments(path); !slices.Equal(got, want) {
		t.Fatalf("control arguments = %q, want %q", got, want)
	}
}

func TestAuthenticatedForwardReadinessBindsPIDAndRetiresPathWithoutStoppingMux(t *testing.T) {
	t.Parallel()

	fixture := newControlSocketFixture(t)
	runner := &scriptedReadinessRunner{
		steps: []readinessRunnerStep{{
			output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\r\n")},
		}},
	}
	readiness := newAuthenticatedForwardReadiness(
		"/opt/warptweet/libexec/openssh/bin/ssh",
		[]string{"LANG=C", "LC_ALL=C"},
		fixture.endpoint,
		runner,
		time.Millisecond,
	)
	if err := readiness.Await(context.Background(), 4321); err != nil {
		t.Fatalf("Await: %v", err)
	}
	if err := readiness.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fixture.removed {
		t.Fatal("control socket survived successful readiness")
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want one check", runner.calls)
	}
	if !strings.Contains(strings.Join(runner.arguments[0], "\x00"), "-O\x00check") {
		t.Fatalf("unexpected control operations: %q", runner.arguments)
	}
	for _, environment := range runner.environments {
		if !slices.Equal(environment, []string{"LANG=C", "LC_ALL=C"}) {
			t.Fatalf("helper environment = %q", environment)
		}
	}
}

func TestAuthenticatedForwardReadinessRejectsForeignMasterWithoutRetiringPath(t *testing.T) {
	t.Parallel()

	fixture := newControlSocketFixture(t)
	runner := &scriptedReadinessRunner{steps: []readinessRunnerStep{{
		output: readinessCommandOutput{stderr: []byte("Master running (pid=9999)\r\n")},
	}}}
	readiness := newAuthenticatedForwardReadiness("/opt/ssh", nil, fixture.endpoint, runner, time.Millisecond)
	err := readiness.Await(context.Background(), 4321)
	if err == nil || !isTerminalReadinessError(err) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Await error = %v, want terminal PID mismatch", err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want check only", runner.calls)
	}
	if err := readiness.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fixture.removed {
		t.Fatal("PID mismatch path was removed by readiness cleanup")
	}
}

func TestAuthenticatedForwardReadinessRejectsRetirementFailure(t *testing.T) {
	t.Parallel()

	fixture := newControlSocketFixture(t)
	want := errors.New("unlink denied")
	fixture.endpoint.retire = func() error { return want }
	runner := &scriptedReadinessRunner{steps: []readinessRunnerStep{{
		output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\r\n")},
	}}}
	readiness := newAuthenticatedForwardReadiness("/opt/ssh", nil, fixture.endpoint, runner, time.Millisecond)
	err := readiness.Await(context.Background(), 4321)
	if err == nil || !isTerminalReadinessError(err) || !errors.Is(err, want) {
		t.Fatalf("Await error = %v, want terminal retirement failure", err)
	}
	if err := readiness.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fixture.removed {
		t.Fatal("failed retirement removed the socket")
	}
}

func TestControlSocketRetirementRejectsRuntimeDirectoryReplacement(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareTestControlSocket(directory)
	if err != nil {
		t.Fatalf("prepareControlSocket: %v", err)
	}
	listener := listenOnTestControlSocket(t, endpoint.Path)
	defer listener.Close()

	displaced := directory + "-displaced"
	t.Cleanup(func() { _ = os.RemoveAll(displaced) })
	if err := os.Rename(directory, displaced); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir replacement: %v", err)
	}
	replacementPath := filepath.Join(directory, controlSocketName)
	replacement := listenOnTestControlSocket(t, replacementPath)
	defer replacement.Close()

	err = endpoint.retireSocket()
	if err == nil || !strings.Contains(err.Error(), "no longer identifies") {
		t.Fatalf("retireSocket error = %v, want directory-replacement rejection", err)
	}
	if _, err := os.Lstat(replacementPath); err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
	_ = endpoint.close()
}

func TestControlSocketRetirementKeepsBoundListenerAliveButUnreachable(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareTestControlSocket(directory)
	if err != nil {
		t.Fatalf("prepareControlSocket: %v", err)
	}
	listener := listenOnTestControlSocket(t, endpoint.Path)
	defer listener.Close()
	queued, err := net.Dial("unix", endpoint.Path)
	if err != nil {
		t.Fatalf("queue connection before retirement: %v", err)
	}
	defer queued.Close()

	if err := endpoint.retireSocket(); err != nil {
		t.Fatalf("retireSocket: %v", err)
	}
	if _, err := os.Lstat(endpoint.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired socket path state = %v, want absent", err)
	}
	if connection, err := net.DialTimeout("unix", endpoint.Path, 10*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("retired control listener remained reachable by pathname")
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept queued connection after retirement: %v", err)
	}
	_ = accepted.Close()
	_ = endpoint.close()
}

func TestControlSocketRetirementRejectsReplacementAfterInitialValidation(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareTestControlSocket(directory)
	if err != nil {
		t.Fatalf("prepareControlSocket: %v", err)
	}
	original := listenOnTestControlSocket(t, endpoint.Path)
	if err := endpoint.validateSocket(); err != nil {
		t.Fatalf("validate original socket: %v", err)
	}
	if err := original.Close(); err != nil {
		t.Fatalf("close original socket: %v", err)
	}
	if err := os.Remove(endpoint.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove original socket: %v", err)
	}
	replacement := listenOnTestControlSocket(t, endpoint.Path)
	defer replacement.Close()

	err = endpoint.retireSocket()
	if err == nil || !strings.Contains(err.Error(), "changed after initial validation") {
		t.Fatalf("retireSocket error = %v, want socket-replacement rejection", err)
	}
	if _, err := os.Lstat(endpoint.Path); err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
	_ = endpoint.close()
}

func TestAuthenticatedForwardReadinessRejectsMalformedSuccessfulCheck(t *testing.T) {
	t.Parallel()

	fixture := newControlSocketFixture(t)
	runner := &scriptedReadinessRunner{steps: []readinessRunnerStep{{
		output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\n")},
	}}}
	readiness := newAuthenticatedForwardReadiness("/opt/ssh", nil, fixture.endpoint, runner, time.Millisecond)
	err := readiness.Await(context.Background(), 4321)
	if err == nil || !isTerminalReadinessError(err) {
		t.Fatalf("Await error = %v, want terminal malformed-evidence rejection", err)
	}
	_ = readiness.Close()
}

func TestAuthenticatedForwardReadinessRetriesWithoutParsingFailureDiagnostics(t *testing.T) {
	t.Parallel()

	fixture := newControlSocketFixture(t)
	runner := &scriptedReadinessRunner{steps: []readinessRunnerStep{
		{output: readinessCommandOutput{stderr: []byte("diagnostic text is not parsed")}, err: errors.New("exit status 255")},
		{output: readinessCommandOutput{stderr: []byte("Master running (pid=4321)\r\n")}},
	}}
	readiness := newAuthenticatedForwardReadiness("/opt/ssh", nil, fixture.endpoint, runner, time.Millisecond)
	if err := readiness.Await(context.Background(), 4321); err != nil {
		t.Fatalf("Await: %v", err)
	}
	_ = readiness.Close()
	if runner.calls != 2 {
		t.Fatalf("runner calls = %d, want failed check and successful check", runner.calls)
	}
}

func TestAuthenticatedForwardReadinessFailsClosedOnInvalidSocket(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareTestControlSocket(directory)
	if err != nil {
		t.Fatalf("prepareControlSocket: %v", err)
	}
	if err := os.WriteFile(endpoint.Path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runner := &scriptedReadinessRunner{}
	readiness := newAuthenticatedForwardReadiness("/opt/ssh", nil, endpoint, runner, time.Millisecond)
	err = readiness.Await(context.Background(), 4321)
	if err == nil || !isTerminalReadinessError(err) || !strings.Contains(err.Error(), "not a Unix-domain socket") {
		t.Fatalf("Await error = %v, want terminal invalid-socket rejection", err)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want zero", runner.calls)
	}
	_ = readiness.Close()
}

func TestAuthenticatedForwardReadinessTimesOutWithoutSocket(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareTestControlSocket(directory)
	if err != nil {
		t.Fatalf("prepareControlSocket: %v", err)
	}
	readiness := newAuthenticatedForwardReadiness(
		"/opt/ssh",
		nil,
		endpoint,
		&scriptedReadinessRunner{},
		time.Millisecond,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err = readiness.Await(ctx, 4321)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Await error = %v, want deadline exceeded", err)
	}
	_ = readiness.Close()
}

func TestPrepareControlSocketRejectsNonPrivateDirectoryAndPreexistingPath(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := prepareTestControlSocket(directory); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("prepareControlSocket error = %v, want mode rejection", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	path := filepath.Join(directory, controlSocketName)
	if err := os.WriteFile(path, []byte("preexisting"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := prepareTestControlSocket(directory); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("prepareControlSocket error = %v, want preexisting-path rejection", err)
	}
}

func TestPrepareControlSocketRejectsCrossPrincipalDirectory(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareControlSocketWithOwners(
		directory,
		func(os.FileInfo) (bool, error) { return false, nil },
		acceptTestAncestorOwner,
	)
	if endpoint != nil || err == nil || !strings.Contains(err.Error(), "effective user") {
		t.Fatalf("prepareControlSocketWithOwners = (%v, %v), want ownership rejection", endpoint, err)
	}
}

func TestPrepareControlSocketRejectsWrongOwnerAncestor(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareControlSocketWithOwners(
		directory,
		fileInfoOwnedByEffectiveUser,
		func(os.FileInfo) (bool, error) { return false, nil },
	)
	if endpoint != nil || err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("prepareControlSocketWithOwners = (%v, %v), want root-owner rejection", endpoint, err)
	}
}

func TestOpenReadinessDirectoryChecksEveryAncestorOwner(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	_, components, err := validateAbsoluteReadinessPath(directory)
	if err != nil {
		t.Fatalf("validateAbsoluteReadinessPath: %v", err)
	}
	ownerChecks := 0
	root, err := openReadinessDirectory(
		directory,
		func(os.FileInfo) (bool, error) {
			ownerChecks++
			return true, nil
		},
	)
	if err != nil {
		t.Fatalf("openReadinessDirectory: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("close readiness directory: %v", err)
	}
	// The filesystem root plus every path component except the service-owned
	// leaf equals the number of path components.
	if ownerChecks != len(components) {
		t.Fatalf("ancestor owner checks = %d, want %d", ownerChecks, len(components))
	}
}

func TestPrepareControlSocketRejectsReplaceableAncestor(t *testing.T) {
	t.Parallel()

	base := newShortPrivateRuntimeDirectory(t)
	replaceable := filepath.Join(base, "replaceable")
	directory := filepath.Join(replaceable, "runtime")
	if err := os.Mkdir(replaceable, 0o770); err != nil {
		t.Fatalf("Mkdir replaceable: %v", err)
	}
	if err := os.Chmod(replaceable, 0o770); err != nil {
		t.Fatalf("Chmod replaceable: %v", err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir runtime: %v", err)
	}
	if _, err := prepareTestControlSocket(directory); err == nil || !strings.Contains(err.Error(), "permit replacement") {
		t.Fatalf("prepareControlSocket error = %v, want replaceable-ancestor rejection", err)
	}
}

func TestPrepareControlSocketRejectsSymlinkComponent(t *testing.T) {
	t.Parallel()

	base := newShortPrivateRuntimeDirectory(t)
	realDirectory := filepath.Join(base, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir real: %v", err)
	}
	linkedDirectory := filepath.Join(base, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := prepareTestControlSocket(linkedDirectory); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("prepareControlSocket error = %v, want symlink rejection", err)
	}
}

func TestAuthenticatedForwardReadinessRejectsRuntimeDirectoryReplacement(t *testing.T) {
	t.Parallel()

	directory := newShortPrivateRuntimeDirectory(t)
	endpoint, err := prepareTestControlSocket(directory)
	if err != nil {
		t.Fatalf("prepareControlSocket: %v", err)
	}
	displaced := directory + "-displaced"
	t.Cleanup(func() { _ = os.RemoveAll(displaced) })
	if err := os.Rename(directory, displaced); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir replacement: %v", err)
	}
	readiness := newAuthenticatedForwardReadiness(
		"/opt/ssh",
		nil,
		endpoint,
		&scriptedReadinessRunner{},
		time.Millisecond,
	)
	err = readiness.Await(context.Background(), 4321)
	if err == nil || !isTerminalReadinessError(err) || !strings.Contains(err.Error(), "no longer identifies") {
		t.Fatalf("Await error = %v, want terminal directory-replacement rejection", err)
	}
	_ = readiness.Close()
}

type controlSocketFixture struct {
	endpoint *fakeReadinessControlEndpoint
	removed  bool
}

func newControlSocketFixture(t *testing.T) *controlSocketFixture {
	t.Helper()
	fixture := &controlSocketFixture{}
	fixture.endpoint = &fakeReadinessControlEndpoint{
		controlPath: "/run/warptweet/tunnels/database-primary/c",
		validate: func() error {
			if fixture.removed {
				return errControlSocketNotReady
			}
			return nil
		},
		retire: func() error {
			fixture.removed = true
			return nil
		},
	}
	return fixture
}

type fakeReadinessControlEndpoint struct {
	controlPath string
	validate    func() error
	retire      func() error
	closed      bool
}

func (endpoint *fakeReadinessControlEndpoint) path() string { return endpoint.controlPath }

func (endpoint *fakeReadinessControlEndpoint) validateSocket() error {
	if endpoint.validate == nil {
		return nil
	}
	return endpoint.validate()
}

func (endpoint *fakeReadinessControlEndpoint) retireSocket() error {
	if endpoint.retire == nil {
		return nil
	}
	return endpoint.retire()
}

func (endpoint *fakeReadinessControlEndpoint) close() error {
	endpoint.closed = true
	return nil
}

func newShortPrivateRuntimeDirectory(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "wt-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	canonical, err := filepath.EvalSymlinks(base)
	if err != nil {
		_ = os.RemoveAll(base)
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(canonical, 0o700); err != nil {
		_ = os.RemoveAll(canonical)
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(canonical) })
	return canonical
}

func prepareTestControlSocket(runtimeDirectory string) (*controlSocketEndpoint, error) {
	return prepareControlSocketWithOwners(
		runtimeDirectory,
		fileInfoOwnedByEffectiveUser,
		acceptTestAncestorOwner,
	)
}

func acceptTestAncestorOwner(os.FileInfo) (bool, error) {
	return true, nil
}

func listenOnTestControlSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on test control socket: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("chmod test control socket: %v", err)
	}
	return listener
}

type readinessRunnerStep struct {
	output readinessCommandOutput
	err    error
	action func() error
}

type scriptedReadinessRunner struct {
	mu           sync.Mutex
	steps        []readinessRunnerStep
	calls        int
	arguments    [][]string
	environments [][]string
}

func (runner *scriptedReadinessRunner) Run(
	_ context.Context,
	_ string,
	environment []string,
	arguments ...string,
) (readinessCommandOutput, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	index := runner.calls
	runner.calls++
	runner.arguments = append(runner.arguments, append([]string(nil), arguments...))
	runner.environments = append(runner.environments, append([]string(nil), environment...))
	if index >= len(runner.steps) {
		return readinessCommandOutput{}, fmt.Errorf("unexpected readiness runner call %d", runner.calls)
	}
	step := runner.steps[index]
	if step.action != nil {
		if err := step.action(); err != nil {
			return step.output, err
		}
	}
	return step.output, step.err
}

func isTerminalReadinessError(err error) bool {
	var terminal interface{ Terminal() bool }
	return errors.As(err, &terminal) && terminal.Terminal()
}
