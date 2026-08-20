package release_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGosecScriptScansFromRepositoryRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX gosec gate is Unix-only")
	}
	t.Parallel()

	root := repositoryRoot(t)
	script := string(readFile(t, filepath.Join(root, "scripts", "check-gosec.sh")))
	cdMark := `CDPATH= cd -- "$WT_REPOSITORY_ROOT"`
	execMark := `exec "$WT_CACHE/gosec" -quiet ./...`
	cdAt := strings.Index(script, cdMark)
	execAt := strings.Index(script, execMark)
	if cdAt < 0 || execAt < 0 || cdAt > execAt {
		t.Fatal("check-gosec.sh must cd to WT_REPOSITORY_ROOT before executing gosec ./...")
	}

	fakeRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(fakeRoot, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(fakeRoot, "scripts", "check-gosec.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	pwdFile := filepath.Join(t.TempDir(), "pwd")
	stubGosec := filepath.Join(bin, "stub-gosec")
	writeExecutable(t, stubGosec, "#!/bin/sh\npwd > \""+pwdFile+"\"\n")
	writeExecutable(t, filepath.Join(bin, "go"), "#!/bin/sh\ninstall -m 0755 \""+stubGosec+"\" \"$GOBIN/gosec\"\n")

	command := exec.Command(scriptPath)
	command.Dir = t.TempDir()
	command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("check-gosec.sh: %v\n%s", err, output)
	}
	got := strings.TrimSpace(string(readFile(t, pwdFile)))
	want, err := filepath.EvalSymlinks(fakeRoot)
	if err != nil {
		want = fakeRoot
	}
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		gotResolved = got
	}
	if gotResolved != want {
		t.Fatalf("gosec cwd=%q want %q", got, fakeRoot)
	}
}
