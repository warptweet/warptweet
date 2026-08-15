//go:build plan9

package enrollment

import (
	"os"
	"syscall"
)

func lockOwnerAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Plan 9 has no POSIX signal 0 probe. An empty note is a liveness check:
	// post fails when the process is gone.
	if err := process.Signal(syscall.Note("")); err != nil {
		return false
	}
	return true
}
