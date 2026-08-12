//go:build linux

package engine

import (
	"errors"
	"os"
	"syscall"
)

func requireProductionRootOwner(_ string, info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine Linux file ownership")
	}
	if status.Uid != 0 {
		return errors.New("must be owned by root")
	}
	return nil
}

func requireProductionRootGroupOwner(_ string, info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine Linux file ownership")
	}
	if status.Uid != 0 || status.Gid != 0 {
		return errors.New("must be owned by root:root")
	}
	return nil
}
