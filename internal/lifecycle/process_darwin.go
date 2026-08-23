//go:build darwin

package lifecycle

import "golang.org/x/sys/unix"

func processStartIdentity(pid int) (uint64, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, false
	}
	start := info.Proc.P_starttime
	return uint64(start.Sec)<<32 | uint64(uint32(start.Usec)), true
}
