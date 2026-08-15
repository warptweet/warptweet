//go:build !unix && !windows && !plan9

package enrollment

func lockOwnerAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Unsupported non-Unix targets: refuse to treat unknown PIDs as live.
	return false
}
