//go:build unix

package grantsession

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const lockAcquireTimeout = 3 * time.Second

func flockExclusive(file *os.File) error {
	return FlockExclusive(file)
}

func flockUnlock(file *os.File) error {
	return FlockUnlock(file)
}

// FlockExclusive takes an exclusive flock on file, retrying until a deadline.
func FlockExclusive(file *os.File) error {
	deadline := time.Now().Add(lockAcquireTimeout)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("lock acquisition timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// FlockUnlock releases a flock on file.
func FlockUnlock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
