//go:build !linux && !darwin

package lifecycle

func processStartIdentity(pid int) (uint64, bool) {
	_ = pid
	return 0, false
}
