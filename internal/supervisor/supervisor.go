// Package supervisor owns the lifecycle of a single OpenSSH tunnel process.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	defaultStableWindow    = time.Minute
	defaultStartupTimeout  = 30 * time.Second
	defaultMaximumAttempts = 10
	terminateGrace         = 2 * time.Second
)

// Policy controls bounded restart behavior for an established tunnel.
type Policy struct {
	Restart        bool
	InitialBackoff time.Duration
	MaximumBackoff time.Duration
	StableWindow   time.Duration
	StartupTimeout time.Duration
	// MaximumAttempts bounds consecutive failed launches. Zero selects the
	// fixed safe default. A stable run resets the consecutive-failure count,
	// but the subsequent exit still counts as the first attempt in the new
	// sequence.
	MaximumAttempts int
}

// Command is the closed executable invocation prepared by the engine package.
type Command struct {
	Path   string
	Args   []string
	Env    []string
	Stdout io.Writer
	Stderr io.Writer
}

// Runner executes a command once. It exists so lifecycle behavior can be
// tested without invoking a network client.
type Runner interface {
	Run(context.Context, Command) error
}

// Process is one directly started, foreground data-plane process. Wait must be
// called exactly once. Terminate must not reap the process. Kill is a last-resort
// force stop after Terminate grace.
type Process interface {
	PID() int
	Wait() error
	Terminate() error
	Kill() error
}

// Launcher starts a command without waiting for it. Readiness is deliberately
// impossible to implement with Runner because the gate must bind its evidence
// to the foreground child's PID while racing process exit.
type Launcher interface {
	Start(context.Context, Command) (Process, error)
}

// ReadinessGate proves that the authenticated SSH transport and configured
// local-forward listener existed for the supplied foreground process. It does
// not claim that the forwarding target accepts connections.
type ReadinessGate interface {
	Await(context.Context, int) error
	Close() error
}

// CommandProvider prepares and attests the exact command immediately before a
// process launch. A provider error is terminal and the process is not started.
type CommandProvider func(context.Context) (Command, error)

// ReadyCommand pairs one exact invocation with its one-shot readiness witness.
// A fresh value must be prepared for every launch attempt.
type ReadyCommand struct {
	Command   Command
	Readiness ReadinessGate
}

// ReadyCommandProvider prepares and attests one managed launch attempt.
type ReadyCommandProvider func(context.Context) (ReadyCommand, error)

// ReadyEvent is emitted only after PID-bound authenticated-forward readiness
// succeeds and the child has not already exited.
type ReadyEvent struct {
	Attempt int
	PID     int
	Time    time.Time
}

// ReadyNotifier lets the command layer log readiness and notify its service
// manager at the only valid lifecycle boundary. Returning an error is terminal
// and causes the child to be terminated and reaped.
type ReadyNotifier func(context.Context, ReadyEvent) error

// State is the typed lifecycle state of a managed tunnel attempt.
type State string

const (
	StatePreparing         State = "preparing"
	StateStarting          State = "starting"
	StateAwaitingReadiness State = "awaiting_readiness"
	StateReady             State = "ready"
	StateBackoff           State = "backoff"
	StateStopping          State = "stopping"
	StateStopped           State = "stopped"
	StateFailed            State = "failed"
)

// Transition is non-secret lifecycle evidence suitable for an observer.
type Transition struct {
	State   State
	Attempt int
	PID     int
	Time    time.Time
	Err     error
}

// Observer receives ordered state changes. It must return promptly and must
// not make authorization decisions; ReadyNotifier owns the fail-closed Ready
// side effect.
type Observer func(context.Context, Transition)

// ExecRunner runs the data-plane process directly, without a shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, command Command) error {
	process, err := (ExecLauncher{}).Start(ctx, command)
	if err != nil {
		return err
	}
	return process.Wait()
}

// ExecLauncher starts the data-plane process directly, without a shell.
type ExecLauncher struct{}

func (ExecLauncher) Start(ctx context.Context, command Command) (Process, error) {
	if ctx == nil {
		return nil, errors.New("supervised command context is required")
	}
	if command.Path == "" {
		return nil, errors.New("supervised command path is required")
	}
	if command.Env == nil {
		return nil, errors.New("supervised command environment is required")
	}
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	process.Env = append([]string(nil), command.Env...)
	process.Stdin = nil
	process.Stdout = command.Stdout
	process.Stderr = command.Stderr
	if err := process.Start(); err != nil {
		return nil, err
	}
	return &execProcess{command: process}, nil
}

type execProcess struct {
	command *exec.Cmd
}

func (process *execProcess) PID() int {
	return process.command.Process.Pid
}

func (process *execProcess) Wait() error {
	return process.command.Wait()
}

func (process *execProcess) Terminate() error {
	err := process.command.Process.Signal(syscall.SIGTERM)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (process *execProcess) Kill() error {
	err := process.command.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// Supervisor restarts failed tunnels according to a bounded policy.
type Supervisor struct {
	Runner   Runner
	Launcher Launcher
	Logger   *slog.Logger
	Observer Observer
	now      func() time.Time
	wait     func(context.Context, time.Duration) error
}

// Run blocks until the context is cancelled, a one-shot command exits, or a
// non-restarting policy observes an exit.
func (supervisor Supervisor) Run(ctx context.Context, command Command, policy Policy) error {
	return supervisor.RunPrepared(ctx, func(context.Context) (Command, error) {
		return command, nil
	}, policy)
}

// RunPrepared invokes provider immediately before every initial launch and
// restart. Preparation failure is terminal because launching without current
// attestation would weaken the process boundary.
func (supervisor Supervisor) RunPrepared(
	ctx context.Context,
	provider CommandProvider,
	policy Policy,
) error {
	if err := validatePolicy(policy); err != nil {
		return err
	}
	if provider == nil {
		return errors.New("supervised command provider is required")
	}
	if supervisor.Runner == nil {
		supervisor.Runner = ExecRunner{}
	}
	if supervisor.Logger == nil {
		supervisor.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if supervisor.now == nil {
		supervisor.now = time.Now
	}
	if supervisor.wait == nil {
		supervisor.wait = waitContext
	}
	stableWindow := policy.StableWindow
	if stableWindow == 0 {
		stableWindow = defaultStableWindow
	}

	backoff := policy.InitialBackoff
	attempt := 0
	consecutiveFailures := 0
	maximumAttempts := policy.MaximumAttempts
	if maximumAttempts == 0 {
		maximumAttempts = defaultMaximumAttempts
	}
	for {
		command, err := provider(ctx)
		if err != nil {
			if ctx.Err() != nil {
				supervisor.Logger.Info("tunnel process stopped", "reason", "context_cancelled")
				return nil
			}
			return fmt.Errorf("prepare supervised command: %w", err)
		}
		if command.Path == "" {
			return errors.New("supervised command path is required")
		}

		attempt++
		started := supervisor.now()
		supervisor.Logger.Info("tunnel process starting", "attempt", attempt)
		err = supervisor.Runner.Run(ctx, command)
		runtime := supervisor.now().Sub(started)

		if ctx.Err() != nil {
			supervisor.Logger.Info("tunnel process stopped", "reason", "context_cancelled")
			return nil
		}
		if !policy.Restart {
			if err == nil {
				return nil
			}
			return fmt.Errorf("tunnel process exited: %w", err)
		}
		if runtime >= stableWindow {
			backoff = policy.InitialBackoff
			consecutiveFailures = 0
		}
		consecutiveFailures++
		if consecutiveFailures >= maximumAttempts {
			lastErr := err
			if lastErr == nil {
				lastErr = errors.New("tunnel process exited successfully while restart was required")
			}
			return fmt.Errorf("tunnel process reached %d consecutive failed attempts: %w", maximumAttempts, lastErr)
		}

		attributes := []any{"attempt", attempt, "restart_backoff", backoff.String()}
		if err != nil {
			attributes = append(attributes, "error", err)
		}
		supervisor.Logger.Warn("tunnel process exited; restart scheduled", attributes...)
		if err := supervisor.wait(ctx, backoff); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("wait before tunnel restart: %w", err)
		}
		backoff = nextBackoff(backoff, policy.MaximumBackoff)
	}
}

// RunPreparedReady starts one foreground child at a time, races its exit
// against a bounded PID-bound readiness gate, and invokes notifier only after
// the gate succeeds. Every failure after Start terminates and reaps the child.
func (supervisor Supervisor) RunPreparedReady(
	ctx context.Context,
	provider ReadyCommandProvider,
	policy Policy,
	notifier ReadyNotifier,
) error {
	if ctx == nil {
		return errors.New("supervisor context is required")
	}
	if err := validatePolicy(policy); err != nil {
		return err
	}
	if provider == nil {
		return errors.New("ready command provider is required")
	}
	if supervisor.Launcher == nil {
		supervisor.Launcher = ExecLauncher{}
	}
	supervisor.initialize()

	stableWindow := policy.StableWindow
	if stableWindow == 0 {
		stableWindow = defaultStableWindow
	}
	startupTimeout := policy.StartupTimeout
	if startupTimeout == 0 {
		startupTimeout = defaultStartupTimeout
	}

	backoff := policy.InitialBackoff
	attempt := 0
	consecutiveFailures := 0
	maximumAttempts := policy.MaximumAttempts
	if maximumAttempts == 0 {
		maximumAttempts = defaultMaximumAttempts
	}
	for {
		supervisor.transition(ctx, StatePreparing, attempt+1, 0, nil)
		prepared, err := provider(ctx)
		if err != nil {
			if ctx.Err() != nil {
				supervisor.transition(ctx, StateStopped, attempt, 0, nil)
				return nil
			}
			supervisor.transition(ctx, StateFailed, attempt+1, 0, err)
			return fmt.Errorf("prepare ready supervised command: %w", err)
		}
		if prepared.Readiness == nil {
			return errors.New("supervised readiness gate is required")
		}
		if prepared.Command.Path == "" {
			closeErr := prepared.Readiness.Close()
			return errors.Join(errors.New("supervised command path is required"), closeErr)
		}

		attempt++
		result := supervisor.runReadyAttempt(
			ctx,
			attempt,
			prepared,
			startupTimeout,
			notifier,
		)
		if result.stopped {
			supervisor.transition(ctx, StateStopped, attempt, result.pid, nil)
			return nil
		}
		if result.readyRuntime >= stableWindow {
			backoff = policy.InitialBackoff
			consecutiveFailures = 0
		}
		if result.terminal || isTerminalFailure(result.err) {
			supervisor.transition(ctx, StateFailed, attempt, result.pid, result.err)
			return fmt.Errorf("managed tunnel attempt failed terminally: %w", result.err)
		}
		if !policy.Restart {
			supervisor.transition(ctx, StateFailed, attempt, result.pid, result.err)
			return fmt.Errorf("managed tunnel attempt failed: %w", result.err)
		}
		consecutiveFailures++
		if consecutiveFailures >= maximumAttempts {
			supervisor.transition(ctx, StateFailed, attempt, result.pid, result.err)
			return fmt.Errorf("managed tunnel reached %d consecutive failed attempts: %w", maximumAttempts, result.err)
		}

		supervisor.Logger.Warn(
			"tunnel process failed; restart scheduled",
			"attempt", attempt,
			"restart_backoff", backoff.String(),
			"error", result.err,
		)
		supervisor.transition(ctx, StateBackoff, attempt, result.pid, result.err)
		if err := supervisor.wait(ctx, backoff); err != nil {
			if ctx.Err() != nil {
				supervisor.transition(ctx, StateStopped, attempt, result.pid, nil)
				return nil
			}
			return fmt.Errorf("wait before tunnel restart: %w", err)
		}
		backoff = nextBackoff(backoff, policy.MaximumBackoff)
	}
}

type readyAttemptResult struct {
	pid          int
	err          error
	readyRuntime time.Duration
	terminal     bool
	stopped      bool
}

func (supervisor Supervisor) runReadyAttempt(
	ctx context.Context,
	attempt int,
	prepared ReadyCommand,
	startupTimeout time.Duration,
	notifier ReadyNotifier,
) readyAttemptResult {
	supervisor.transition(ctx, StateStarting, attempt, 0, nil)
	supervisor.Logger.Info("tunnel process starting", "attempt", attempt)
	process, err := supervisor.Launcher.Start(ctx, prepared.Command)
	if err != nil {
		closeErr := terminalReadinessClose(prepared.Readiness.Close())
		return readyAttemptResult{err: errors.Join(fmt.Errorf("start tunnel process: %w", err), closeErr)}
	}
	pid := process.PID()
	if pid <= 0 {
		waitErr := terminateAndReap(process, nil)
		closeErr := terminalReadinessClose(prepared.Readiness.Close())
		return readyAttemptResult{
			pid:      pid,
			err:      errors.Join(errors.New("started tunnel process has an invalid PID"), waitErr, closeErr),
			terminal: true,
		}
	}

	waitResult := make(chan error, 1)
	go func() { waitResult <- process.Wait() }()
	readinessContext, cancelReadiness := context.WithTimeout(ctx, startupTimeout)
	readinessResult := make(chan error, 1)
	go func() { readinessResult <- prepared.Readiness.Await(readinessContext, pid) }()
	supervisor.transition(ctx, StateAwaitingReadiness, attempt, pid, nil)

	select {
	case processErr := <-waitResult:
		cancelReadiness()
		readinessErr := <-readinessResult
		closeErr := terminalReadinessClose(prepared.Readiness.Close())
		if ctx.Err() != nil {
			return readyAttemptResult{pid: pid, stopped: true}
		}
		if isTerminalFailure(readinessErr) {
			return readyAttemptResult{pid: pid, err: errors.Join(readinessErr, closeErr), terminal: true}
		}
		return readyAttemptResult{
			pid: pid,
			err: errors.Join(
				processExitError("before authenticated-forward readiness", processErr),
				closeErr,
			),
		}

	case readinessErr := <-readinessResult:
		cancelReadiness()
		if readinessErr != nil {
			waitErr := terminateAndReap(process, waitResult)
			closeErr := terminalReadinessClose(prepared.Readiness.Close())
			if ctx.Err() != nil {
				return readyAttemptResult{pid: pid, stopped: true}
			}
			return readyAttemptResult{
				pid:      pid,
				err:      errors.Join(fmt.Errorf("establish authenticated-forward readiness: %w", readinessErr), waitErr, closeErr),
				terminal: isTerminalFailure(readinessErr),
			}
		}
		if ctx.Err() != nil {
			waitErr := terminateAndReap(process, waitResult)
			closeErr := terminalReadinessClose(prepared.Readiness.Close())
			if closeErr != nil {
				supervisor.Logger.Error("close readiness gate during shutdown", "error", closeErr)
			}
			if waitErr != nil {
				supervisor.Logger.Error("reap tunnel process during shutdown", "error", waitErr)
			}
			return readyAttemptResult{pid: pid, stopped: true}
		}
		if closeErr := terminalReadinessClose(prepared.Readiness.Close()); closeErr != nil {
			waitErr := terminateAndReap(process, waitResult)
			return readyAttemptResult{
				pid:      pid,
				err:      errors.Join(closeErr, waitErr),
				terminal: true,
			}
		}
		select {
		case processErr := <-waitResult:
			return readyAttemptResult{
				pid: pid,
				err: processExitError(
					"at the authenticated-forward readiness boundary",
					processErr,
				),
			}
		default:
		}

		readyAt := supervisor.now()
		if notifier != nil {
			if notifyErr := notifier(ctx, ReadyEvent{Attempt: attempt, PID: pid, Time: readyAt}); notifyErr != nil {
				waitErr := terminateAndReap(process, waitResult)
				return readyAttemptResult{
					pid:      pid,
					err:      errors.Join(terminalSupervisorError{"publish tunnel readiness", notifyErr}, waitErr),
					terminal: true,
				}
			}
		}
		supervisor.transition(ctx, StateReady, attempt, pid, nil)
		supervisor.Logger.Info("tunnel authenticated forward ready", "attempt", attempt, "pid", pid)

		select {
		case processErr := <-waitResult:
			return readyAttemptResult{
				pid:          pid,
				err:          processExitError("after authenticated-forward readiness", processErr),
				readyRuntime: supervisor.now().Sub(readyAt),
			}
		case <-ctx.Done():
			supervisor.transition(ctx, StateStopping, attempt, pid, nil)
			_ = terminateAndReap(process, waitResult)
			return readyAttemptResult{pid: pid, stopped: true}
		}

	case <-ctx.Done():
		cancelReadiness()
		supervisor.transition(ctx, StateStopping, attempt, pid, nil)
		waitErr := terminateAndReap(process, waitResult)
		readinessErr := <-readinessResult
		closeErr := prepared.Readiness.Close()
		if closeErr != nil {
			supervisor.Logger.Error("close readiness gate during shutdown", "error", closeErr)
		}
		if waitErr != nil {
			supervisor.Logger.Error("reap tunnel process during shutdown", "error", waitErr)
		}
		if readinessErr != nil && !errors.Is(readinessErr, context.Canceled) {
			supervisor.Logger.Debug("readiness gate ended during shutdown", "error", readinessErr)
		}
		return readyAttemptResult{pid: pid, stopped: true}
	}
}

func terminateAndReap(process Process, waitResult <-chan error) error {
	if waitResult != nil {
		select {
		case processErr := <-waitResult:
			return processErr
		default:
		}
	}
	terminateErr := process.Terminate()
	var waitErr error
	if waitResult == nil {
		waitErr = process.Wait()
		return errors.Join(terminateErr, waitErr)
	}
	timer := time.NewTimer(terminateGrace)
	defer timer.Stop()
	select {
	case waitErr = <-waitResult:
		return errors.Join(terminateErr, waitErr)
	case <-timer.C:
		terminateErr = errors.Join(terminateErr, process.Kill())
		killTimer := time.NewTimer(terminateGrace)
		defer killTimer.Stop()
		select {
		case waitErr = <-waitResult:
			return errors.Join(terminateErr, waitErr)
		case <-killTimer.C:
			return errors.Join(terminateErr, errors.New("process did not exit after kill"))
		}
	}
}

func processExitError(boundary string, err error) error {
	if err == nil {
		return fmt.Errorf("tunnel process exited successfully %s", boundary)
	}
	return fmt.Errorf("tunnel process exited %s: %w", boundary, err)
}

type terminalSupervisorError struct {
	action string
	err    error
}

func (failure terminalSupervisorError) Error() string {
	return fmt.Sprintf("%s: %v", failure.action, failure.err)
}

func (failure terminalSupervisorError) Unwrap() error { return failure.err }
func (terminalSupervisorError) Terminal() bool        { return true }

func terminalReadinessClose(err error) error {
	if err == nil {
		return nil
	}
	return terminalSupervisorError{"close readiness gate", err}
}

type terminalFailure interface {
	Terminal() bool
}

func isTerminalFailure(err error) bool {
	if err == nil {
		return false
	}
	var failure terminalFailure
	return errors.As(err, &failure) && failure.Terminal()
}

func (supervisor *Supervisor) initialize() {
	if supervisor.Logger == nil {
		supervisor.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if supervisor.now == nil {
		supervisor.now = time.Now
	}
	if supervisor.wait == nil {
		supervisor.wait = waitContext
	}
}

func (supervisor Supervisor) transition(
	ctx context.Context,
	state State,
	attempt int,
	pid int,
	err error,
) {
	if supervisor.Observer == nil {
		return
	}
	supervisor.Observer(ctx, Transition{
		State:   state,
		Attempt: attempt,
		PID:     pid,
		Time:    supervisor.now(),
		Err:     err,
	})
}

func validatePolicy(policy Policy) error {
	if policy.InitialBackoff <= 0 {
		return errors.New("initial restart backoff must be positive")
	}
	if policy.MaximumBackoff < policy.InitialBackoff {
		return errors.New("maximum restart backoff must be at least the initial backoff")
	}
	if policy.StableWindow < 0 {
		return errors.New("stable window must not be negative")
	}
	if policy.StartupTimeout < 0 {
		return errors.New("startup timeout must not be negative")
	}
	if policy.MaximumAttempts < 0 {
		return errors.New("maximum attempts must not be negative")
	}
	return nil
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
