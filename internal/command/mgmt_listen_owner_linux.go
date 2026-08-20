//go:build linux

package command

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func processOwnsTCPListen(pid int, endpoint netip.AddrPort) bool {
	if pid <= 0 || !endpoint.IsValid() {
		return false
	}
	want := listenKey(endpoint)
	inodes := map[uint64]struct{}{}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		collectListenInodes(table, want, inodes)
	}
	if len(inodes) == 0 {
		return false
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fmt.Sprintf("/proc/%d/fd", pid), entry.Name()))
		if err != nil {
			continue
		}
		inode, ok := parseSocketInode(target)
		if !ok {
			continue
		}
		if _, owned := inodes[inode]; owned {
			return true
		}
	}
	return false
}

func listenKey(endpoint netip.AddrPort) string {
	port := fmt.Sprintf("%04X", endpoint.Port())
	if endpoint.Addr().Is4() {
		ip := endpoint.Addr().As4()
		return fmt.Sprintf("%02X%02X%02X%02X:%s", ip[3], ip[2], ip[1], ip[0], port)
	}
	ip := endpoint.Addr().As16()
	var b [16]byte
	for i := 0; i < 16; i += 4 {
		b[i] = ip[i+3]
		b[i+1] = ip[i+2]
		b[i+2] = ip[i+1]
		b[i+3] = ip[i]
	}
	return strings.ToUpper(hex.EncodeToString(b[:])) + ":" + port
}

func collectListenInodes(path, wantLocal string, inodes map[uint64]struct{}) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		if !strings.EqualFold(fields[1], wantLocal) {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		inodes[inode] = struct{}{}
	}
}

func parseSocketInode(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), 10, 64)
	return inode, err == nil
}
