package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExecRunnerUsesOnlyPreparedEnvironment(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "process")
	script := "#!/bin/sh\n[ \"${WARPTWEET_TEST_ENV:-}\" = expected ]\n" +
		"[ -z \"${LD_PRELOAD:-}\" ]\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write process fixture: %v", err)
	}
	if err := (ExecRunner{}).Run(context.Background(), Command{
		Path: path,
		Env:  []string{"WARPTWEET_TEST_ENV=expected"},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := (ExecRunner{}).Run(context.Background(), Command{Path: path}); err == nil || !strings.Contains(err.Error(), "environment is required") {
		t.Fatalf("nil-environment Run error = %v", err)
	}
}

type sequenceRunner struct {
	errors []error
	calls  int
}

func (runner *sequenceRunner) Run(_ context.Context, _ Command) error {
	runner.calls++
	if runner.calls > len(runner.errors) {
		return nil
	}
	return runner.errors[runner.calls-1]
}

func TestRunOnceReturnsProcessFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("authentication rejected")
	runner := &sequenceRunner{errors: []error{want}}
	supervisor := Supervisor{Runner: runner}
	err := supervisor.Run(context.Background(), Command{Path: "/opt/warptweet/ssh"}, Policy{
		Restart:        false,
		InitialBackoff: time.Second,
		MaximumBackoff: time.Second,
	})
	if !errors.Is(err, want) {
		t.Fatalf("Run error = %v, want wrapped %v", err, want)
	}
}

func TestRestartBackoffIsBounded(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	runner := &sequenceRunner{errors: []error{
		errors.New("first"),
		errors.New("second"),
		errors.New("third"),
	}}
	var waits []time.Duration
	supervisor := Supervisor{
		Runner: runner,
		now:    time.Now,
		wait: func(_ context.Context, duration time.Duration) error {
			waits = append(waits, duration)
			if len(waits) == 3 {
				cancel()
				return context.Canceled
			}
			return nil
		},
	}
	err := supervisor.Run(ctx, Command{Path: "/opt/warptweet/ssh"}, Policy{
		Restart:        true,
		InitialBackoff: time.Second,
		MaximumBackoff: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("wait count = %d, want %d", len(waits), len(want))
	}
	for index := range want {
		if waits[index] != want[index] {
			t.Errorf("wait[%d] = %s, want %s", index, waits[index], want[index])
		}
	}
}

func TestRunPreparedStopsAtMaximumConsecutiveAttempts(t *testing.T) {
	t.Parallel()

	runner := &sequenceRunner{errors: []error{
		errors.New("first"),
		errors.New("second"),
		errors.New("third"),
	}}
	waits := 0
	err := (Supervisor{
		Runner: runner,
		wait: func(context.Context, time.Duration) error {
			waits++
			return nil
		},
	}).Run(context.Background(), Command{Path: "/opt/warptweet/ssh"}, Policy{
		Restart:         true,
		InitialBackoff:  time.Millisecond,
		MaximumBackoff:  time.Millisecond,
		MaximumAttempts: 3,
	})
	if err == nil || !strings.Contains(err.Error(), "3 consecutive failed attempts") {
		t.Fatalf("Run error = %v, want bounded-attempt failure", err)
	}
	if runner.calls != 3 || waits != 2 {
		t.Fatalf("calls=%d waits=%d, want 3/2", runner.calls, waits)
	}
}

func TestPolicyRejectsUnboundedOrdering(t *testing.T) {
	t.Parallel()

	err := (Supervisor{}).Run(context.Background(), Command{Path: "/bin/false"}, Policy{
		Restart:        true,
		InitialBackoff: 2 * time.Second,
		MaximumBackoff: time.Second,
	})
	if err == nil {
		t.Fatal("Run accepted maximum backoff below initial backoff")
	}
}

func TestRunPreparedInvokesProviderBeforeEveryLaunch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	runner := &sequenceRunner{errors: []error{
		errors.New("first"),
		errors.New("second"),
	}}
	providerCalls := 0
	var waits int
	supervisor := Supervisor{
		Runner: runner,
		now:    time.Now,
		wait: func(_ context.Context, _ time.Duration) error {
			waits++
			if waits == 2 {
				cancel()
				return context.Canceled
			}
			return nil
		},
	}
	err := supervisor.RunPrepared(ctx, func(context.Context) (Command, error) {
		providerCalls++
		return Command{Path: "/opt/warptweet/ssh"}, nil
	}, Policy{
		Restart:        true,
		InitialBackoff: time.Second,
		MaximumBackoff: time.Second,
	})
	if err != nil {
		t.Fatalf("RunPrepared: %v", err)
	}
	if providerCalls != 2 {
		t.Fatalf("provider calls = %d, want 2", providerCalls)
	}
	if runner.calls != providerCalls {
		t.Fatalf("runner calls = %d, provider calls = %d", runner.calls, providerCalls)
	}
}

func TestRunPreparedDoesNotExecuteAfterProviderFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("attestation failed")
	runner := &sequenceRunner{}
	supervisor := Supervisor{Runner: runner}
	err := supervisor.RunPrepared(context.Background(), func(context.Context) (Command, error) {
		return Command{}, want
	}, Policy{
		Restart:        true,
		InitialBackoff: time.Second,
		MaximumBackoff: time.Second,
	})
	if !errors.Is(err, want) {
		t.Fatalf("RunPrepared error = %v, want wrapped %v", err, want)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestRunPreparedStopsWhenRestartAttestationFails(t *testing.T) {
	t.Parallel()

	want := errors.New("restart attestation failed")
	runner := &sequenceRunner{errors: []error{errors.New("process exited")}}
	providerCalls := 0
	supervisor := Supervisor{
		Runner: runner,
		wait: func(context.Context, time.Duration) error {
			return nil
		},
	}
	err := supervisor.RunPrepared(context.Background(), func(context.Context) (Command, error) {
		providerCalls++
		if providerCalls == 2 {
			return Command{}, want
		}
		return Command{Path: "/opt/warptweet/ssh"}, nil
	}, Policy{
		Restart:        true,
		InitialBackoff: time.Second,
		MaximumBackoff: time.Second,
	})
	if !errors.Is(err, want) {
		t.Fatalf("RunPrepared error = %v, want wrapped %v", err, want)
	}
	if providerCalls != 2 {
		t.Fatalf("provider calls = %d, want 2", providerCalls)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
}

func TestRunPreparedRejectsNilProvider(t *testing.T) {
	t.Parallel()

	err := (Supervisor{}).RunPrepared(context.Background(), nil, Policy{
		InitialBackoff: time.Second,
		MaximumBackoff: time.Second,
	})
	if err == nil {
		t.Fatal("RunPrepared accepted a nil provider")
	}
}

func TestRunPreparedReadyNotifiesOnlyAfterPIDBoundGate(t *testing.T) {
	t.Parallel()

	process := newTestProcess(4321)
	gateStarted := make(chan int, 1)
	releaseGate := make(chan struct{})
	gate := &testReadinessGate{await: func(ctx context.Context, pid int) error {
		gateStarted <- pid
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-releaseGate:
			return nil
		}
	}}
	launcher := &testLauncher{processes: []*testProcess{process}}
	readyEvents := make(chan ReadyEvent, 1)
	var transitionsMu sync.Mutex
	var transitions []State
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- (Supervisor{
			Launcher: launcher,
			Observer: func(_ context.Context, transition Transition) {
				transitionsMu.Lock()
				transitions = append(transitions, transition.State)
				transitionsMu.Unlock()
			},
		}).RunPreparedReady(
			ctx,
			func(context.Context) (ReadyCommand, error) {
				return testReadyCommand(gate), nil
			},
			testReadyPolicy(false),
			func(_ context.Context, event ReadyEvent) error {
				readyEvents <- event
				return nil
			},
		)
	}()

	if pid := <-gateStarted; pid != 4321 {
		t.Fatalf("gate PID = %d, want 4321", pid)
	}
	select {
	case event := <-readyEvents:
		t.Fatalf("notifier fired before gate success: %+v", event)
	default:
	}
	close(releaseGate)
	event := <-readyEvents
	if event.PID != 4321 || event.Attempt != 1 || event.Time.IsZero() {
		t.Fatalf("ready event = %+v", event)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("RunPreparedReady: %v", err)
	}
	if !process.wasTerminated() || process.waitCalls.Load() != 1 {
		t.Fatalf("process terminated=%t wait calls=%d, want true/1", process.wasTerminated(), process.waitCalls.Load())
	}
	if gate.closeCalls.Load() != 1 {
		t.Fatalf("gate close calls = %d, want 1", gate.closeCalls.Load())
	}
	transitionsMu.Lock()
	gotTransitions := append([]State(nil), transitions...)
	transitionsMu.Unlock()
	wantTransitions := []State{
		StatePreparing,
		StateStarting,
		StateAwaitingReadiness,
		StateReady,
		StateStopping,
		StateStopped,
	}
	if len(gotTransitions) != len(wantTransitions) {
		t.Fatalf("transitions = %q, want %q", gotTransitions, wantTransitions)
	}
	for index := range wantTransitions {
		if gotTransitions[index] != wantTransitions[index] {
			t.Fatalf("transitions[%d] = %q, want %q", index, gotTransitions[index], wantTransitions[index])
		}
	}
}

func TestRunPreparedReadyFailureTerminatesAndReapsWithoutNotification(t *testing.T) {
	t.Parallel()

	want := errors.New("authentication evidence unavailable")
	process := newTestProcess(4321)
	gate := &testReadinessGate{await: func(context.Context, int) error { return want }}
	notifications := 0
	err := (Supervisor{Launcher: &testLauncher{processes: []*testProcess{process}}}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) { return testReadyCommand(gate), nil },
		testReadyPolicy(false),
		func(context.Context, ReadyEvent) error {
			notifications++
			return nil
		},
	)
	if !errors.Is(err, want) {
		t.Fatalf("RunPreparedReady error = %v, want wrapped %v", err, want)
	}
	if notifications != 0 {
		t.Fatalf("notifications = %d, want 0", notifications)
	}
	if !process.wasTerminated() || process.waitCalls.Load() != 1 || gate.closeCalls.Load() != 1 {
		t.Fatalf(
			"terminated=%t wait=%d close=%d, want true/1/1",
			process.wasTerminated(),
			process.waitCalls.Load(),
			gate.closeCalls.Load(),
		)
	}
}

func TestRunPreparedReadyTerminalIntegrityFailureDoesNotRestart(t *testing.T) {
	t.Parallel()

	process := newTestProcess(4321)
	gate := &testReadinessGate{await: func(context.Context, int) error {
		return testTerminalFailure{errors.New("foreign control-master PID")}
	}}
	providerCalls := 0
	waits := 0
	err := (Supervisor{
		Launcher: &testLauncher{processes: []*testProcess{process}},
		wait: func(context.Context, time.Duration) error {
			waits++
			return nil
		},
	}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) {
			providerCalls++
			return testReadyCommand(gate), nil
		},
		testReadyPolicy(true),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "foreign control-master PID") {
		t.Fatalf("RunPreparedReady error = %v, want integrity failure", err)
	}
	if providerCalls != 1 || waits != 0 {
		t.Fatalf("provider calls=%d waits=%d, want 1/0", providerCalls, waits)
	}
}

func TestRunPreparedReadyProcessExitWinsBeforeReadiness(t *testing.T) {
	t.Parallel()

	want := errors.New("ssh authentication rejected")
	process := newTestProcess(4321)
	process.exit(want)
	gate := &testReadinessGate{await: func(ctx context.Context, _ int) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	err := (Supervisor{Launcher: &testLauncher{processes: []*testProcess{process}}}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) { return testReadyCommand(gate), nil },
		testReadyPolicy(false),
		nil,
	)
	if !errors.Is(err, want) {
		t.Fatalf("RunPreparedReady error = %v, want wrapped %v", err, want)
	}
	if process.waitCalls.Load() != 1 || gate.closeCalls.Load() != 1 {
		t.Fatalf("wait calls=%d close calls=%d, want 1/1", process.waitCalls.Load(), gate.closeCalls.Load())
	}
}

func TestRunPreparedReadyNotifierFailureTerminatesAndReaps(t *testing.T) {
	t.Parallel()

	want := errors.New("sd_notify failed")
	process := newTestProcess(4321)
	gate := &testReadinessGate{await: func(context.Context, int) error { return nil }}
	err := (Supervisor{Launcher: &testLauncher{processes: []*testProcess{process}}}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) { return testReadyCommand(gate), nil },
		testReadyPolicy(true),
		func(context.Context, ReadyEvent) error { return want },
	)
	if !errors.Is(err, want) {
		t.Fatalf("RunPreparedReady error = %v, want wrapped %v", err, want)
	}
	if !process.wasTerminated() || process.waitCalls.Load() != 1 {
		t.Fatalf("terminated=%t wait calls=%d, want true/1", process.wasTerminated(), process.waitCalls.Load())
	}
}

func TestRunPreparedReadyOnceReturnsPostReadyProcessFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("transport lost")
	process := newTestProcess(4321)
	gate := &testReadinessGate{await: func(context.Context, int) error { return nil }}
	err := (Supervisor{Launcher: &testLauncher{processes: []*testProcess{process}}}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) { return testReadyCommand(gate), nil },
		testReadyPolicy(false),
		func(context.Context, ReadyEvent) error {
			process.exit(want)
			return nil
		},
	)
	if !errors.Is(err, want) {
		t.Fatalf("RunPreparedReady error = %v, want wrapped %v", err, want)
	}
}

func TestRunPreparedReadyStableWindowStartsAtReady(t *testing.T) {
	t.Parallel()

	processes := []*testProcess{newTestProcess(1001), newTestProcess(1002)}
	launcher := &testLauncher{processes: processes}
	clock := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	now := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	advance := func(duration time.Duration) {
		clockMu.Lock()
		clock = clock.Add(duration)
		clockMu.Unlock()
	}
	providerCalls := 0
	waits := make([]time.Duration, 0, 2)
	ctx, cancel := context.WithCancel(context.Background())
	supervisor := Supervisor{
		Launcher: launcher,
		now:      now,
		wait: func(_ context.Context, duration time.Duration) error {
			waits = append(waits, duration)
			if len(waits) == 2 {
				cancel()
				return context.Canceled
			}
			return nil
		},
	}
	err := supervisor.RunPreparedReady(
		ctx,
		func(context.Context) (ReadyCommand, error) {
			providerCalls++
			if providerCalls == 1 {
				return testReadyCommand(&testReadinessGate{await: func(context.Context, int) error {
					return errors.New("first startup failed")
				}}), nil
			}
			return testReadyCommand(&testReadinessGate{await: func(context.Context, int) error {
				advance(10 * time.Second)
				return nil
			}}), nil
		},
		Policy{
			Restart:        true,
			InitialBackoff: time.Second,
			MaximumBackoff: 4 * time.Second,
			StableWindow:   5 * time.Second,
			StartupTimeout: time.Second,
		},
		func(_ context.Context, event ReadyEvent) error {
			processes[event.Attempt-1].exit(errors.New("immediate post-ready exit"))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("RunPreparedReady: %v", err)
	}
	wantWaits := []time.Duration{time.Second, 2 * time.Second}
	if len(waits) != len(wantWaits) {
		t.Fatalf("waits = %v, want %v", waits, wantWaits)
	}
	for index := range wantWaits {
		if waits[index] != wantWaits[index] {
			t.Fatalf("waits[%d] = %v, want %v", index, waits[index], wantWaits[index])
		}
	}
}

func TestRunPreparedReadyStartupTimeoutTerminatesAndReaps(t *testing.T) {
	t.Parallel()

	process := newTestProcess(4321)
	gate := &testReadinessGate{await: func(ctx context.Context, _ int) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	policy := testReadyPolicy(false)
	policy.StartupTimeout = 5 * time.Millisecond
	err := (Supervisor{Launcher: &testLauncher{processes: []*testProcess{process}}}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) { return testReadyCommand(gate), nil },
		policy,
		nil,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunPreparedReady error = %v, want deadline exceeded", err)
	}
	if !process.wasTerminated() || process.waitCalls.Load() != 1 {
		t.Fatalf("terminated=%t wait calls=%d, want true/1", process.wasTerminated(), process.waitCalls.Load())
	}
}

func TestRunPreparedReadyStopsAtMaximumConsecutiveAttempts(t *testing.T) {
	t.Parallel()

	processes := []*testProcess{newTestProcess(1001), newTestProcess(1002), newTestProcess(1003)}
	for index, process := range processes {
		process.exit(fmt.Errorf("attempt %d failed", index+1))
	}
	launcher := &testLauncher{processes: processes}
	waits := 0
	err := (Supervisor{
		Launcher: launcher,
		wait: func(context.Context, time.Duration) error {
			waits++
			return nil
		},
	}).RunPreparedReady(
		context.Background(),
		func(context.Context) (ReadyCommand, error) {
			return testReadyCommand(&testReadinessGate{await: func(ctx context.Context, _ int) error {
				<-ctx.Done()
				return ctx.Err()
			}}), nil
		},
		Policy{
			Restart:         true,
			InitialBackoff:  time.Millisecond,
			MaximumBackoff:  time.Millisecond,
			MaximumAttempts: 3,
			StartupTimeout:  time.Second,
		},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "3 consecutive failed attempts") {
		t.Fatalf("RunPreparedReady error = %v, want bounded-attempt failure", err)
	}
	if launcher.calls != 3 || waits != 2 {
		t.Fatalf("calls=%d waits=%d, want 3/2", launcher.calls, waits)
	}
}

type testProcess struct {
	pidValue      int
	exitResult    chan error
	terminated    chan struct{}
	terminateOnce sync.Once
	waitCalls     atomic.Int32
}

func newTestProcess(pid int) *testProcess {
	return &testProcess{
		pidValue:   pid,
		exitResult: make(chan error, 1),
		terminated: make(chan struct{}),
	}
}

func (process *testProcess) PID() int { return process.pidValue }

func (process *testProcess) Wait() error {
	process.waitCalls.Add(1)
	return <-process.exitResult
}

func (process *testProcess) Terminate() error {
	process.terminateOnce.Do(func() {
		close(process.terminated)
		select {
		case process.exitResult <- nil:
		default:
		}
	})
	return nil
}

func (process *testProcess) exit(err error) {
	process.exitResult <- err
}

func (process *testProcess) wasTerminated() bool {
	select {
	case <-process.terminated:
		return true
	default:
		return false
	}
}

type testLauncher struct {
	mu        sync.Mutex
	processes []*testProcess
	calls     int
}

func (launcher *testLauncher) Start(context.Context, Command) (Process, error) {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	if launcher.calls >= len(launcher.processes) {
		return nil, errors.New("unexpected test launch")
	}
	process := launcher.processes[launcher.calls]
	launcher.calls++
	return process, nil
}

type testReadinessGate struct {
	await      func(context.Context, int) error
	closeErr   error
	closeCalls atomic.Int32
}

func (gate *testReadinessGate) Await(ctx context.Context, pid int) error {
	return gate.await(ctx, pid)
}

func (gate *testReadinessGate) Close() error {
	gate.closeCalls.Add(1)
	return gate.closeErr
}

type testTerminalFailure struct{ error }

func (testTerminalFailure) Terminal() bool { return true }

func testReadyCommand(gate ReadinessGate) ReadyCommand {
	return ReadyCommand{
		Command: Command{
			Path: "/opt/warptweet/libexec/openssh/bin/ssh",
			Env:  []string{"LANG=C", "LC_ALL=C"},
		},
		Readiness: gate,
	}
}

func testReadyPolicy(restart bool) Policy {
	return Policy{
		Restart:        restart,
		InitialBackoff: time.Millisecond,
		MaximumBackoff: time.Millisecond,
		StartupTimeout: time.Second,
	}
}
