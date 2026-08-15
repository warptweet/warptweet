//go:build !unix

package enrollment

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// lockPathExclusive uses an O_EXCL lock file that holds the owner PID for
// diagnostics. The open file handle is the real lock: peers cannot remove the
// path while the owner keeps it open on platforms that enforce share delete
// rules. PID values are not a stable lock identity (they can be reused), so a
// closed lock file that still contains os.Getpid() is always treated as stale
// and reclaimed by the next caller.
func lockPathExclusive(directory, name, label string) (unlock func(), err error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(directory, name)
	owner := os.Getpid()

	const attempts = 20
	for attempt := 0; attempt < attempts; attempt++ {
		file, createErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr == nil {
			if _, writeErr := fmt.Fprintf(file, "%d\n", owner); writeErr != nil {
				_ = file.Close()
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("lock %s: %w", label, writeErr)
			}
			return func() {
				_ = file.Close()
				raw, readErr := os.ReadFile(lockPath)
				if readErr != nil {
					return
				}
				if strings.TrimSpace(string(raw)) != strconv.Itoa(owner) {
					return
				}
				_ = os.Remove(lockPath)
			}, nil
		}
		if !os.IsExist(createErr) {
			return nil, fmt.Errorf("lock %s: %w", label, createErr)
		}

		raw, readErr := os.ReadFile(lockPath)
		if readErr != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		holder, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
		// Reclaim when the recorded holder is missing, invalid, our own PID
		// (closed leftover from a prior incarnation; PID is not reusable lock
		// identity), or a dead process. Prefer Remove: if a peer still holds
		// the file open, Remove fails and we report busy.
		stale := parseErr != nil || holder <= 0 || holder == owner || !lockOwnerAlive(holder)
		if stale {
			_ = os.Remove(lockPath)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if remErr := os.Remove(lockPath); remErr == nil || os.IsNotExist(remErr) {
			// OS released the path (holder closed without unlinking).
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("lock %s: held by pid %d", label, holder)
	}
	return nil, fmt.Errorf("lock %s: busy", label)
}
