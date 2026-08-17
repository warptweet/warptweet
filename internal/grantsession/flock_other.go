//go:build !unix

package grantsession

import "os"

func flockExclusive(file *os.File) error { return FlockExclusive(file) }

func flockUnlock(file *os.File) error { return FlockUnlock(file) }

func FlockExclusive(file *os.File) error { return nil }

func FlockUnlock(file *os.File) error { return nil }
