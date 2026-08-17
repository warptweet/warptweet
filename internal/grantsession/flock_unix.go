//go:build unix

package grantsession

import (
	"os"
	"syscall"
)

func flockExclusive(file *os.File) error {
	return FlockExclusive(file)
}

func flockUnlock(file *os.File) error {
	return FlockUnlock(file)
}

// FlockExclusive takes an exclusive flock on file.
func FlockExclusive(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
}

// FlockUnlock releases a flock on file.
func FlockUnlock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
