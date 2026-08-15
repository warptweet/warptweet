//go:build unix

package enrollment

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func lockPathExclusive(directory, name, label string) (unlock func(), err error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(directory, name)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %s: %w", label, err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
