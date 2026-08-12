//go:build darwin

package engine

import (
	"errors"
	"os"
	"syscall"
)

func fileInfoOwnedByRoot(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("file metadata does not contain Darwin stat ownership")
	}
	return stat.Uid == 0, nil
}
