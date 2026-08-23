//go:build unix

package provisioner

import (
	"fmt"
	"os"
	"syscall"
)

func applyUnixSocketOwnership(path string, uid, gid int, mode os.FileMode) error {
	if err := os.Chown(path, uid, gid); err != nil {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return fmt.Errorf("set provisioner socket ownership: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
			return fmt.Errorf("set provisioner socket ownership: %w", err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set provisioner socket mode: %w", err)
	}
	return nil
}
