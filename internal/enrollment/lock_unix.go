//go:build unix

package enrollment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func lockPathExclusive(directory, name, label string, nonBlocking bool) (unlock func(), err error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(directory, name)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if nonBlocking {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), how); err != nil {
		_ = file.Close()
		if nonBlocking && (errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)) {
			return nil, fmt.Errorf("lock %s at %s: %w", label, lockPath, ErrBusy)
		}
		return nil, fmt.Errorf("lock %s: %w", label, err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
