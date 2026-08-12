//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package engine

import (
	"errors"
	"os"
	"syscall"
)

func fileInfoOwnedByEffectiveUser(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("file metadata does not expose a Unix owner")
	}
	return uint64(stat.Uid) == uint64(os.Geteuid()), nil
}
