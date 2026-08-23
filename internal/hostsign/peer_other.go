//go:build !linux

package hostsign

import "net"

func authorizePeer(conn net.Conn, allowUID int) error {
	_ = conn
	_ = allowUID
	return nil
}
