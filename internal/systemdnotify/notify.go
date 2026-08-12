// Package systemdnotify sends bounded service-state notifications to systemd.
package systemdnotify

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

const maximumStatusBytes = 512

// Notifier is an immutable sd_notify transport. An empty socket disables
// notifications for direct command-line use outside systemd.
type Notifier struct {
	socket string
	send   func(string, []byte) error
}

// FromEnvironment constructs a notifier from NOTIFY_SOCKET without retaining
// any other process environment state.
func FromEnvironment(getenv func(string) string) (Notifier, error) {
	if getenv == nil {
		return Notifier{}, errors.New("systemd notification environment reader is required")
	}
	socket := getenv("NOTIFY_SOCKET")
	if socket == "" {
		return Notifier{}, nil
	}
	if strings.ContainsRune(socket, '\x00') {
		return Notifier{}, errors.New("NOTIFY_SOCKET must not contain a NUL byte")
	}
	if socket[0] != '@' && !filepath.IsAbs(socket) {
		return Notifier{}, errors.New("NOTIFY_SOCKET must be an absolute or abstract Unix socket")
	}
	if socket == "@" {
		return Notifier{}, errors.New("NOTIFY_SOCKET abstract name must not be empty")
	}
	return Notifier{socket: socket}, nil
}

// Enabled reports whether systemd supplied a notification socket.
func (notifier Notifier) Enabled() bool {
	return notifier.socket != ""
}

// Ready reports that the authenticated SSH transport and requested local
// listener are ready. It does not claim that the forwarding target is healthy.
func (notifier Notifier) Ready(status string) error {
	return notifier.notify("READY=1", status)
}

// Stopping reports an orderly controller shutdown.
func (notifier Notifier) Stopping(status string) error {
	return notifier.notify("STOPPING=1", status)
}

func (notifier Notifier) notify(state, status string) error {
	if notifier.socket == "" {
		return nil
	}
	if err := validateStatus(status); err != nil {
		return err
	}
	payload := []byte(state + "\nSTATUS=" + status)
	if notifier.send != nil {
		return notifier.send(notifier.socket, payload)
	}
	return sendUnixDatagram(notifier.socket, payload)
}

func sendUnixDatagram(socket string, payload []byte) error {
	addressName := socket
	if addressName[0] == '@' {
		addressName = "\x00" + addressName[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{
		Name: addressName,
		Net:  "unixgram",
	})
	if err != nil {
		return fmt.Errorf("connect to systemd notification socket: %w", err)
	}
	defer connection.Close()

	written, err := connection.Write(payload)
	if err != nil {
		return fmt.Errorf("write systemd notification: %w", err)
	}
	if written != len(payload) {
		return fmt.Errorf("write systemd notification: wrote %d of %d bytes", written, len(payload))
	}
	return nil
}

func validateStatus(status string) error {
	if status == "" {
		return errors.New("systemd notification status is required")
	}
	if len(status) > maximumStatusBytes {
		return fmt.Errorf("systemd notification status exceeds %d bytes", maximumStatusBytes)
	}
	if strings.ContainsAny(status, "\x00\r\n") {
		return errors.New("systemd notification status contains a control character")
	}
	return nil
}
