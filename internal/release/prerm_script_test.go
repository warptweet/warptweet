package release_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrermUpgradeLeavesDataPlaneEnabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux maintainer scripts are POSIX")
	}
	t.Parallel()

	root := repositoryRoot(t)
	prerm := filepath.Join(root, "packaging", "linux", "prerm.sh")

	cases := []struct {
		name        string
		arg         string
		wantStop    bool
		wantRestart bool
	}{
		{name: "debian remove", arg: "remove", wantStop: true},
		{name: "debian deconfigure", arg: "deconfigure", wantStop: true},
		{name: "rpm uninstall", arg: "0", wantStop: true},
		{name: "debian upgrade", arg: "upgrade"},
		{name: "rpm upgrade", arg: "1"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			logPath := filepath.Join(t.TempDir(), "systemctl.log")
			bin := t.TempDir()
			writeExecutable(t, filepath.Join(bin, "id"), "#!/bin/sh\necho 0\n")
			writeExecutable(t, filepath.Join(bin, "systemctl"), systemctlStub(logPath))

			unitsPath := filepath.Join(t.TempDir(), "upgrade-active.units")
			command := exec.Command(prerm, test.arg)
			command.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"LC_ALL=C",
				"WT_UPGRADE_UNITS=" + unitsPath,
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("prerm %s: %v\n%s", test.arg, err, output)
			}
			log := string(readFile(t, logPath))
			hasStop := strings.Contains(log, "stop ") || strings.Contains(log, "disable ")
			hasRestart := strings.Contains(log, "try-restart ")
			if test.wantStop && !hasStop {
				t.Fatalf("uninstall did not stop/disable units:\n%s", log)
			}
			if !test.wantStop && hasStop {
				t.Fatalf("upgrade stopped or disabled units:\n%s", log)
			}
			if !test.wantStop {
				recorded, _ := os.ReadFile(unitsPath)
				if !strings.Contains(string(recorded), "warptweet-sshd.service") {
					t.Fatalf("upgrade did not record active units:\n%s", recorded)
				}
			}
			if test.wantRestart && !hasRestart {
				t.Fatalf("upgrade did not try-restart units:\n%s", log)
			}
			if !test.wantRestart && hasRestart {
				t.Fatalf("prerm try-restarted units:\n%s", log)
			}
		})
	}
}

func systemctlStub(logPath string) string {
	return `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$1" in
    is-active|is-enabled)
        exit 0
        ;;
    list-units|list-unit-files)
        echo "warptweet-tunnel@db.service loaded active running"
        exit 0
        ;;
    daemon-reload|try-restart|stop|disable)
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
`
}
