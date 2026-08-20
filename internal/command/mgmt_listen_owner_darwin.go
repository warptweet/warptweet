//go:build darwin

package command

import (
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

func processOwnsTCPListen(pid int, endpoint netip.AddrPort) bool {
	if pid <= 0 || !endpoint.IsValid() {
		return false
	}
	cmd := exec.Command("lsof", "-nP", "-a", "-p", strconv.Itoa(pid),
		"-iTCP:"+strconv.Itoa(int(endpoint.Port())), "-sTCP:LISTEN")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	text := string(output)
	return strings.Contains(text, endpoint.Addr().String()) || strings.Contains(text, "*:"+strconv.Itoa(int(endpoint.Port())))
}
