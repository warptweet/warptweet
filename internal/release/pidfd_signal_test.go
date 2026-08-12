package release_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPidfdSignalHelperContract(t *testing.T) {
	t.Parallel()

	helperPath := filepath.Join(repositoryRoot(t), "scripts", "pidfd-signal.py")
	helper := string(readFile(t, helperPath))
	for _, required := range []string{
		"os.pidfd_open",
		"signal.pidfd_send_signal",
		`stat_text.rfind(") ")`,
		"actual_identity != expected_identity",
		"actual_executable != expected_executable",
		`allowed_signals = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}`,
	} {
		if !strings.Contains(helper, required) {
			t.Errorf("pidfd signal helper omits %q", required)
		}
	}
	for _, forbidden := range []string{"os.kill(", "subprocess", "shell=True"} {
		if strings.Contains(helper, forbidden) {
			t.Errorf("pidfd signal helper contains unsafe operation %q", forbidden)
		}
	}
	info, err := os.Stat(helperPath)
	if err != nil {
		t.Fatalf("stat pidfd signal helper: %v", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("pidfd signal helper is group or world writable: %04o", info.Mode().Perm())
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable for helper syntax validation")
	}
	command := exec.Command(
		python,
		"-c",
		"import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))",
		helperPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("parse pidfd signal helper: %v: %s", err, output)
	}
}

func TestPidfdSignalHelperRejectsSubstitutionAndSignalsCapturedProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pidfd signaling is a Linux release-gate primitive")
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep is unavailable")
	}
	process := exec.Command(sleep, "30")
	if err := process.Start(); err != nil {
		t.Fatalf("start pidfd test process: %v", err)
	}
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = process.Process.Kill()
		_ = process.Wait()
	}()

	pid := process.Process.Pid
	identityCommand := exec.Command(python, "-c", `
import os
import sys
pid = int(sys.argv[1])
directory_stat = os.stat(f"/proc/{pid}", follow_symlinks=False)
stat_text = open(f"/proc/{pid}/stat", encoding="ascii").read()
fields = stat_text[stat_text.rfind(") ") + 2:].split()
print(f"{directory_stat.st_dev}:{directory_stat.st_ino}:{fields[19]}")
`, fmt.Sprintf("%d", pid))
	identityOutput, err := identityCommand.CombinedOutput()
	if err != nil {
		t.Fatalf("capture pidfd test process identity: %v: %s", err, identityOutput)
	}
	identity := strings.TrimSpace(string(identityOutput))
	executable, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Fatalf("resolve pidfd test executable: %v", err)
	}
	helperPath := filepath.Join(repositoryRoot(t), "scripts", "pidfd-signal.py")

	mismatch := exec.Command(
		python,
		helperPath,
		fmt.Sprintf("%d", pid),
		"0:0:0",
		executable,
		"TERM",
	)
	mismatchOutput, mismatchError := mismatch.CombinedOutput()
	exitError, ok := mismatchError.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 76 {
		t.Fatalf(
			"pidfd helper accepted substituted identity: error=%v output=%s",
			mismatchError,
			mismatchOutput,
		)
	}

	signalCommand := exec.Command(
		python,
		helperPath,
		fmt.Sprintf("%d", pid),
		identity,
		executable,
		"TERM",
	)
	if output, err := signalCommand.CombinedOutput(); err != nil {
		t.Fatalf("signal captured process through pidfd: %v: %s", err, output)
	}
	wait := make(chan error, 1)
	go func() {
		wait <- process.Wait()
	}()
	select {
	case <-wait:
		waited = true
	case <-time.After(5 * time.Second):
		t.Fatal("pidfd-signaled process did not exit")
	}
}
