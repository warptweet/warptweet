//go:build !linux && !darwin

package command

import "net/netip"

func processOwnsTCPListen(int, netip.AddrPort) bool {
	return false
}
