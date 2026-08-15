//go:build !unix

package command

import "syscall"

func enrollListenSysProcAttr() *syscall.SysProcAttr {
	return nil
}
