package hostsign

import (
	"fmt"
	"net"
	"syscall"
)

func authorizePeer(conn net.Conn, allowUID int) error {
	if allowUID < 0 {
		return nil
	}
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("hostsign requires a unix socket")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, ctrlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if ctrlErr != nil {
		return ctrlErr
	}
	if int(cred.Uid) != allowUID {
		return fmt.Errorf("peer uid %d is not allowed", cred.Uid)
	}
	return nil
}
