package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"warptweet.com/warptweet/internal/artifactprofile"
	"warptweet.com/warptweet/internal/installlayout"
)

const (
	controlSocketTemporarySuffixBytes = 17 // '.' plus OpenSSH's 16-character suffix.
	unixSocketMaximumPathBytes        = 107
	readinessOutputLimit              = 1024
	defaultReadinessPollInterval      = 50 * time.Millisecond
)

var (
	errControlSocketNotReady = errors.New("OpenSSH control socket is not ready")
	errReadinessOutputLimit  = errors.New("OpenSSH readiness output exceeded its limit")
)

// ClientReadiness is the engine-owned lifecycle seam for a one-shot managed
// launch. Its method set is intentionally identical to supervisor.ReadinessGate
// without introducing a package dependency.
type ClientReadiness interface {
	Await(context.Context, int) error
	Close() error
}

// AuthenticatedForwardReadiness is a one-shot witness for one foreground SSH
// process. Success proves that OpenSSH reported the supplied PID after user
// authentication and local-forward listener setup. It deliberately makes no
// claim about reachability or health of the forwarding target.
type AuthenticatedForwardReadiness struct {
	binaryPath  string
	environment []string
	control     readinessControlEndpoint
	runner      readinessCommandRunner
	poll        time.Duration
}

// Await implements supervisor.ReadinessGate without coupling engine to the
// lifecycle package.
func (readiness *AuthenticatedForwardReadiness) Await(ctx context.Context, childPID int) error {
	if readiness == nil || readiness.control == nil {
		return readinessIntegrityError{message: "authenticated-forward readiness has no control endpoint"}
	}
	if ctx == nil {
		return readinessIntegrityError{message: "authenticated-forward readiness context is required"}
	}
	if childPID <= 0 {
		return readinessIntegrityError{message: "authenticated-forward readiness requires a positive child PID"}
	}
	if readiness.runner == nil {
		return readinessIntegrityError{message: "authenticated-forward readiness runner is required"}
	}
	if readiness.poll <= 0 {
		return readinessIntegrityError{message: "authenticated-forward readiness poll interval must be positive"}
	}

	for {
		err := readiness.control.validateSocket()
		switch {
		case err == nil:
			err = readiness.checkAndRetire(ctx, childPID)
			if err == nil || !errors.Is(err, errControlSocketNotReady) {
				return err
			}
			if err := waitReadinessPoll(ctx, readiness.poll); err != nil {
				return err
			}
		case errors.Is(err, errControlSocketNotReady):
			if err := waitReadinessPoll(ctx, readiness.poll); err != nil {
				return err
			}
		default:
			return readinessIntegrityError{message: "validate OpenSSH control socket", err: err}
		}
	}
}

// Close releases the descriptor anchor after Await has retired the validated
// control pathname. On failed readiness, it deliberately does not remove a
// path that was never bound to the expected child PID.
func (readiness *AuthenticatedForwardReadiness) Close() error {
	if readiness == nil || readiness.control == nil {
		return nil
	}
	return readiness.control.close()
}

func (readiness *AuthenticatedForwardReadiness) checkAndRetire(ctx context.Context, childPID int) error {
	output, err := readiness.runner.Run(
		ctx,
		readiness.binaryPath,
		readiness.environment,
		controlCheckArguments(readiness.control.path())...,
	)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, errReadinessOutputLimit) {
			return readinessIntegrityError{message: "OpenSSH control check exceeded its output limit", err: err}
		}
		// A valid socket may be visible immediately before its mux listener
		// accepts. Do not parse failure diagnostics; retry from full validation.
		return errControlSocketNotReady
	}
	reportedPID, err := parseControlCheckOutput(output)
	if err != nil {
		return readinessIntegrityError{message: "parse successful OpenSSH control check", err: err}
	}
	if reportedPID != childPID {
		return readinessIntegrityError{message: fmt.Sprintf(
			"OpenSSH control master PID %d does not match foreground child PID %d",
			reportedPID,
			childPID,
		)}
	}
	// Do not ask OpenSSH to stop its mux listener. In a foreground
	// SessionType=none process, -O stop also marks the session closed and can
	// terminate the tunnel. Retiring only the descriptor-anchored pathname
	// preserves the master's bound listener descriptor while making the
	// one-shot readiness authority unreachable.
	if err := readiness.control.retireSocket(); err != nil {
		return readinessIntegrityError{message: "retire PID-bound OpenSSH control socket", err: err}
	}
	return nil
}

func newAuthenticatedForwardReadiness(
	binaryPath string,
	environment []string,
	control readinessControlEndpoint,
	runner readinessCommandRunner,
	poll time.Duration,
) *AuthenticatedForwardReadiness {
	return &AuthenticatedForwardReadiness{
		binaryPath:  binaryPath,
		environment: append([]string(nil), environment...),
		control:     control,
		runner:      runner,
		poll:        poll,
	}
}

func managedClientPolicy(runtimeDirectory string, spec ClientSpec) (clientPolicy, error) {
	runtimeRoot := installlayout.ClientRuntimeRoot
	if selected, err := artifactprofile.Current(); err == nil && selected.Layout.ClientRuntimeRoot != "" {
		runtimeRoot = selected.Layout.ClientRuntimeRoot
	}
	return managedClientPolicyAtRoot(runtimeDirectory, spec, runtimeRoot)
}

func managedClientPolicyAtRoot(
	runtimeDirectory string,
	spec ClientSpec,
	requiredRoot string,
) (clientPolicy, error) {
	if err := validateClientSpec(spec); err != nil {
		return clientPolicy{}, err
	}
	if !filepath.IsAbs(requiredRoot) || filepath.Clean(requiredRoot) != requiredRoot {
		return clientPolicy{}, errors.New("managed runtime root must be an absolute clean path")
	}
	expectedDirectory := filepath.Join(requiredRoot, spec.TunnelID)
	if runtimeDirectory != expectedDirectory {
		return clientPolicy{}, fmt.Errorf(
			"managed runtime directory must be exactly %q for tunnel %q",
			expectedDirectory,
			spec.TunnelID,
		)
	}
	return newClientPolicy(spec, filepath.Join(runtimeDirectory, controlSocketName))
}

func validateControlPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("OpenSSH control path must be an absolute clean path")
	}
	if strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("OpenSSH control path contains a forbidden control character")
	}
	if len(path)+controlSocketTemporarySuffixBytes > unixSocketMaximumPathBytes {
		return fmt.Errorf(
			"OpenSSH control path is %d bytes; path plus %d-byte temporary suffix must not exceed %d bytes",
			len(path),
			controlSocketTemporarySuffixBytes,
			unixSocketMaximumPathBytes,
		)
	}
	return nil
}

func controlCheckArguments(controlPath string) []string {
	return []string{
		"-F", "none",
		"-q",
		"-o", "BatchMode=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=" + controlPath,
		"-o", "ControlPersist=no",
		"-O", "check",
		hostAlias,
	}
}

func parseControlCheckOutput(output readinessCommandOutput) (int, error) {
	if len(output.stdout) != 0 {
		return 0, fmt.Errorf("OpenSSH -O check wrote %d unexpected stdout bytes", len(output.stdout))
	}
	const prefix = "Master running (pid="
	const suffix = ")\r\n"
	line := string(output.stderr)
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
		return 0, errors.New("OpenSSH -O check stderr did not match its exact pinned format")
	}
	rawPID := strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)
	pid, err := strconv.Atoi(rawPID)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != rawPID {
		return 0, errors.New("OpenSSH -O check reported a malformed PID")
	}
	return pid, nil
}

func waitReadinessPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type readinessIntegrityError struct {
	message string
	err     error
}

func (failure readinessIntegrityError) Error() string {
	if failure.err == nil {
		return failure.message
	}
	return failure.message + ": " + failure.err.Error()
}

func (failure readinessIntegrityError) Unwrap() error { return failure.err }
func (readinessIntegrityError) Terminal() bool        { return true }

type readinessCommandOutput struct {
	stdout []byte
	stderr []byte
}

type readinessCommandRunner interface {
	Run(context.Context, string, []string, ...string) (readinessCommandOutput, error)
}

type execReadinessCommandRunner struct{}

func (execReadinessCommandRunner) Run(
	ctx context.Context,
	path string,
	environment []string,
	arguments ...string,
) (readinessCommandOutput, error) {
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = append([]string(nil), environment...)
	var stdout limitedReadinessBuffer
	var stderr limitedReadinessBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := readinessCommandOutput{stdout: stdout.bytes(), stderr: stderr.bytes()}
	if stdout.overflow || stderr.overflow {
		return result, errors.Join(errReadinessOutputLimit, err)
	}
	return result, err
}

type limitedReadinessBuffer struct {
	buffer   bytes.Buffer
	overflow bool
}

func (buffer *limitedReadinessBuffer) Write(input []byte) (int, error) {
	written := len(input)
	remaining := readinessOutputLimit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return written, nil
	}
	if len(input) > remaining {
		buffer.overflow = true
		input = input[:remaining]
	}
	_, _ = buffer.buffer.Write(input)
	return written, nil
}

func (buffer *limitedReadinessBuffer) bytes() []byte {
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

type controlSocketEndpoint struct {
	Path  string
	state *controlSocketState
}

type readinessControlEndpoint interface {
	path() string
	validateSocket() error
	retireSocket() error
	close() error
}

func (endpoint *controlSocketEndpoint) path() string {
	if endpoint == nil {
		return ""
	}
	return endpoint.Path
}

type controlSocketState struct {
	once          sync.Once
	socketMu      sync.Mutex
	root          *os.Root
	directory     string
	name          string
	leafOwner     fileOwnershipChecker
	ancestorOwner fileOwnershipChecker
	socket        os.FileInfo
	err           error
}

func prepareControlSocket(runtimeDirectory string) (*controlSocketEndpoint, error) {
	return prepareControlSocketWithOwners(
		runtimeDirectory,
		fileInfoOwnedByEffectiveUser,
		fileInfoOwnedByRoot,
	)
}

func prepareControlSocketWithOwners(
	runtimeDirectory string,
	leafOwner fileOwnershipChecker,
	ancestorOwner fileOwnershipChecker,
) (*controlSocketEndpoint, error) {
	if leafOwner == nil {
		return nil, errors.New("control-socket leaf ownership checker is required")
	}
	if ancestorOwner == nil {
		return nil, errors.New("control-socket ancestor ownership checker is required")
	}
	canonicalDirectory, err := canonicalReadinessDirectory(runtimeDirectory, ancestorOwner)
	if err != nil {
		return nil, err
	}
	root, err := openReadinessDirectory(canonicalDirectory, ancestorOwner)
	if err != nil {
		return nil, fmt.Errorf("open managed runtime directory: %w", err)
	}
	retainRoot := false
	defer func() {
		if !retainRoot {
			_ = root.Close()
		}
	}()

	directoryInfo, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect managed runtime directory: %w", err)
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf(
			"managed runtime directory permissions are %04o, want a real mode-0700 directory",
			directoryInfo.Mode().Perm(),
		)
	}
	owned, err := leafOwner(directoryInfo)
	if err != nil {
		return nil, fmt.Errorf("inspect managed runtime directory ownership: %w", err)
	}
	if !owned {
		return nil, errors.New("managed runtime directory must be owned by the effective user")
	}

	endpoint := &controlSocketEndpoint{
		Path: filepath.Join(canonicalDirectory, controlSocketName),
		state: &controlSocketState{
			root:          root,
			directory:     canonicalDirectory,
			name:          controlSocketName,
			leafOwner:     leafOwner,
			ancestorOwner: ancestorOwner,
		},
	}
	if err := validateControlPath(endpoint.Path); err != nil {
		return nil, err
	}
	if err := endpoint.validateDirectoryIdentity(); err != nil {
		return nil, err
	}
	if err := removeStaleControlSocket(root, controlSocketName, endpoint.Path); err != nil {
		return nil, err
	}

	retainRoot = true
	return endpoint, nil
}

func removeStaleControlSocket(root *os.Root, name, path string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed OpenSSH control path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("managed OpenSSH control path already exists")
	}
	connection, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("managed OpenSSH control path already exists")
	}
	if !isDefinitiveSocketRefusal(dialErr) {
		return fmt.Errorf("probe managed OpenSSH control path: %w", dialErr)
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale OpenSSH control path: %w", err)
	}
	return nil
}

func isDefinitiveSocketRefusal(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func (endpoint *controlSocketEndpoint) validateSocket() error {
	if endpoint == nil || endpoint.state == nil || endpoint.state.root == nil {
		return errors.New("control endpoint has no verified directory handle")
	}
	pathRoot, err := endpoint.openVerifiedPathRoot()
	if err != nil {
		return err
	}
	defer func() { _ = pathRoot.Close() }()

	anchored, err := endpoint.state.root.Lstat(endpoint.state.name)
	if errors.Is(err, os.ErrNotExist) {
		return errControlSocketNotReady
	}
	if err != nil {
		return fmt.Errorf("inspect anchored OpenSSH control socket: %w", err)
	}
	byPath, err := pathRoot.Lstat(endpoint.state.name)
	if err != nil {
		return fmt.Errorf("inspect absolute OpenSSH control socket: %w", err)
	}
	if anchored.Mode()&os.ModeSymlink != 0 || anchored.Mode()&os.ModeSocket == 0 {
		return errors.New("OpenSSH control path is not a Unix-domain socket")
	}
	if anchored.Mode().Perm() != 0o600 {
		return fmt.Errorf("OpenSSH control socket permissions are %04o, want 0600", anchored.Mode().Perm())
	}
	owned, err := endpoint.state.leafOwner(anchored)
	if err != nil {
		return fmt.Errorf("inspect OpenSSH control socket ownership: %w", err)
	}
	if !owned {
		return errors.New("OpenSSH control socket must be owned by the effective user")
	}
	if byPath.Mode()&os.ModeSymlink != 0 || byPath.Mode()&os.ModeSocket == 0 ||
		!os.SameFile(anchored, byPath) {
		return errors.New("OpenSSH control socket path does not identify the anchored socket")
	}
	endpoint.state.socketMu.Lock()
	defer endpoint.state.socketMu.Unlock()
	if endpoint.state.socket != nil && !os.SameFile(endpoint.state.socket, anchored) {
		return errors.New("OpenSSH control socket changed after initial validation")
	}
	endpoint.state.socket = anchored
	return nil
}

func (endpoint *controlSocketEndpoint) retireSocket() error {
	if endpoint == nil || endpoint.state == nil || endpoint.state.root == nil {
		return errors.New("control endpoint has no verified directory handle")
	}
	// Revalidate immediately before the descriptor-relative unlink. The
	// service-owned mode-0700 directory excludes cross-principal replacement;
	// the retained root prevents ancestor or absolute-path substitution.
	if err := endpoint.validateSocket(); err != nil {
		return fmt.Errorf("revalidate OpenSSH control socket before retirement: %w", err)
	}
	if err := endpoint.state.root.Remove(endpoint.state.name); err != nil {
		return fmt.Errorf("unlink anchored OpenSSH control socket: %w", err)
	}
	return endpoint.requireRemoved()
}

func (endpoint *controlSocketEndpoint) requireRemoved() error {
	if endpoint == nil || endpoint.state == nil || endpoint.state.root == nil {
		return errors.New("control endpoint has no verified directory handle")
	}
	pathRoot, err := endpoint.openVerifiedPathRoot()
	if err != nil {
		return err
	}
	defer func() { _ = pathRoot.Close() }()
	for description, root := range map[string]*os.Root{
		"anchored": endpoint.state.root,
		"absolute": pathRoot,
	} {
		if _, err := root.Lstat(endpoint.state.name); err == nil {
			return fmt.Errorf("%s OpenSSH control socket still exists after retirement", description)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s retired OpenSSH control socket: %w", description, err)
		}
	}
	return nil
}

func (endpoint *controlSocketEndpoint) validateDirectoryIdentity() error {
	pathRoot, err := openReadinessDirectory(
		endpoint.state.directory,
		endpoint.state.ancestorOwner,
	)
	if err != nil {
		return fmt.Errorf("reopen managed runtime directory by absolute path: %w", err)
	}
	defer func() { _ = pathRoot.Close() }()
	anchored, err := endpoint.state.root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect anchored managed runtime directory: %w", err)
	}
	byPath, err := pathRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect absolute managed runtime directory: %w", err)
	}
	if !os.SameFile(anchored, byPath) {
		return errors.New("managed runtime directory path no longer identifies the anchored directory")
	}
	return nil
}

func (endpoint *controlSocketEndpoint) openVerifiedPathRoot() (*os.Root, error) {
	pathRoot, err := openReadinessDirectory(
		endpoint.state.directory,
		endpoint.state.ancestorOwner,
	)
	if err != nil {
		return nil, fmt.Errorf("reopen managed runtime directory by absolute path: %w", err)
	}
	anchored, err := endpoint.state.root.Stat(".")
	if err != nil {
		_ = pathRoot.Close()
		return nil, fmt.Errorf("inspect anchored managed runtime directory: %w", err)
	}
	byPath, err := pathRoot.Stat(".")
	if err != nil {
		_ = pathRoot.Close()
		return nil, fmt.Errorf("inspect absolute managed runtime directory: %w", err)
	}
	if !os.SameFile(anchored, byPath) {
		_ = pathRoot.Close()
		return nil, errors.New("managed runtime directory path no longer identifies the anchored directory")
	}
	return pathRoot, nil
}

func (endpoint *controlSocketEndpoint) close() error {
	if endpoint == nil || endpoint.state == nil {
		return nil
	}
	endpoint.state.once.Do(func() {
		endpoint.state.err = endpoint.state.root.Close()
	})
	return endpoint.state.err
}
