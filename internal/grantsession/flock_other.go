//go:build !unix

package grantsession

import "os"

// Grant sessions are Linux-only. These no-op stubs exist so the package builds
// on other platforms; registration itself fails closed in process_other.go.
func flockExclusive(file *os.File) error { return FlockExclusive(file) }

func flockUnlock(file *os.File) error { return FlockUnlock(file) }

func FlockExclusive(file *os.File) error { return nil }

func FlockUnlock(file *os.File) error { return nil }
