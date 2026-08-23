//go:build linux

package lifecycle

import (
	"bytes"
	"os"
	"strconv"
)

func processStartIdentity(pid int) (uint64, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	idx := bytes.LastIndexByte(raw, ')')
	if idx < 0 || idx+2 >= len(raw) {
		return 0, false
	}
	fields := bytes.Fields(raw[idx+2:])
	if len(fields) < 20 {
		return 0, false
	}
	start, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0, false
	}
	return start, true
}
