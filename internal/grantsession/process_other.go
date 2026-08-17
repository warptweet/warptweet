//go:build !linux

package grantsession

import (
	"fmt"
	"strings"
	"syscall"
	"time"
)

func inspectProcess(pid int) (ProcessIdentity, error) {
	return ProcessIdentity{}, fmt.Errorf("grant session process identity requires Linux")
}

func currentBootID() (string, error) {
	return "", fmt.Errorf("grant session boot identity requires Linux")
}

func signalIdentity(identity ProcessIdentity, signal syscall.Signal) error {
	return fmt.Errorf("grant session signaling requires Linux")
}

func identityAlive(identity ProcessIdentity) bool {
	return false
}

func waitIdentityGone(identity ProcessIdentity, deadline time.Duration) bool {
	return false
}

func looksLikeWarpTweetSession(identity ProcessIdentity) bool {
	return strings.HasSuffix(identity.Exe, "/libexec/sshd-session") || strings.HasSuffix(identity.Exe, "/sbin/sshd")
}

func peerPID(conn syscall.Conn) (int, error) {
	return 0, fmt.Errorf("grant session peer credentials require Linux")
}
