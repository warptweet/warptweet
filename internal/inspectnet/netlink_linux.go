//go:build linux

package inspectnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// KernelRouteLookup performs one RTM_GETROUTE lookup on NETLINK_ROUTE.
func KernelRouteLookup(family int, dst netip.Addr) (RouteReply, error) {
	req, err := BuildGetRouteLookup(family, dst)
	if err != nil {
		return RouteReply{}, err
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return RouteReply{}, fmt.Errorf("inspect-network: netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return RouteReply{}, fmt.Errorf("inspect-network: netlink bind: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return RouteReply{}, fmt.Errorf("inspect-network: netlink getsockname: %w", err)
	}
	local, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return RouteReply{}, fmt.Errorf("inspect-network: unexpected netlink sockaddr %T", sa)
	}
	binary.LittleEndian.PutUint32(req[12:16], local.Pid)

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return RouteReply{}, fmt.Errorf("inspect-network: netlink send: %w", err)
	}

	buf := make([]byte, 64<<10)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return RouteReply{}, fmt.Errorf("inspect-network: netlink recv: %w", err)
	}
	if n <= 0 {
		return RouteReply{Evidence: "empty netlink datagram"}, nil
	}
	reply, err := ParseRouteMessages(buf[:n])
	if err != nil {
		var nlErr netlinkErrno
		if asNetlinkErrno(err, &nlErr) && nlErr.unreachable() {
			if reply.Evidence == "" {
				reply.Evidence = nlErr.Error()
			}
			return reply, nil
		}
		return RouteReply{}, err
	}
	return reply, nil
}
