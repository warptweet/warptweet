//go:build linux

package grantsession

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	sysPidfdOpen       = 434
	sysPidfdSendSignal = 424
	sshdSessionSuffix  = "/libexec/sshd-session"
)

func inspectProcess(pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, fmt.Errorf("invalid pid")
	}
	bootID, err := currentBootID()
	if err != nil {
		return ProcessIdentity{}, err
	}
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read process exe: %w", err)
	}
	startTime, err := linuxStartTime(pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{BootID: bootID, PID: pid, StartTime: startTime, Exe: exe}, nil
}

func currentBootID() (string, error) {
	contents, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	bootID := strings.TrimSpace(string(contents))
	if bootID == "" {
		return "", fmt.Errorf("boot id is empty")
	}
	return bootID, nil
}

func linuxStartTime(pid int) (string, error) {
	contents, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	closeParen := strings.LastIndexByte(string(contents), ')')
	if closeParen < 0 || closeParen+1 >= len(contents) {
		return "", fmt.Errorf("parse /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(contents[closeParen+1:]))
	if len(fields) < 20 {
		return "", fmt.Errorf("parse /proc/%d/stat starttime", pid)
	}
	return fields[19], nil
}

func reopenPidfd(identity ProcessIdentity) (int, error) {
	fd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(identity.PID), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	current, err := inspectProcess(identity.PID)
	if err != nil {
		_ = syscall.Close(int(fd))
		return -1, err
	}
	if current.BootID != identity.BootID || current.StartTime != identity.StartTime || current.Exe != identity.Exe {
		_ = syscall.Close(int(fd))
		return -1, errIdentityGone
	}
	return int(fd), nil
}

func signalIdentity(identity ProcessIdentity, signal syscall.Signal) error {
	fd, err := reopenPidfd(identity)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, errIdentityGone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	defer syscall.Close(fd)
	_, _, errno := syscall.Syscall6(sysPidfdSendSignal, uintptr(fd), uintptr(signal), 0, 0, 0, 0)
	if errno != 0 && errno != syscall.ESRCH {
		return errno
	}
	return nil
}

func identityAlive(identity ProcessIdentity) bool {
	current, err := inspectProcess(identity.PID)
	if err != nil {
		return false
	}
	return current.BootID == identity.BootID && current.StartTime == identity.StartTime && current.Exe == identity.Exe
}

func waitIdentityGone(identity ProcessIdentity, deadline time.Duration) bool {
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if !identityAlive(identity) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !identityAlive(identity)
}

func looksLikeWarpTweetSession(identity ProcessIdentity) bool {
	return strings.HasSuffix(identity.Exe, sshdSessionSuffix) || strings.HasSuffix(identity.Exe, "/sbin/sshd")
}

func peerPID(conn syscall.Conn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		ucred, getErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if getErr != nil {
			sysErr = getErr
			return
		}
		pid = int(ucred.Pid)
	})
	if err != nil {
		return 0, err
	}
	return pid, sysErr
}
