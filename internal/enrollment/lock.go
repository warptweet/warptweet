package enrollment

import "errors"

// ErrBusy means a non-blocking exclusive lock is already held.
var ErrBusy = errors.New("resource is busy")

// WithExclusiveLock runs fn while holding a cross-process exclusive lock named
// under directory. Unlock always runs, including when fn returns an error.
func WithExclusiveLock(directory, name string, fn func() error) error {
	unlock, err := lockPathExclusive(directory, name, "resource", false)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// WithNonBlockingExclusiveLock is WithExclusiveLock using LOCK_NB.
func WithNonBlockingExclusiveLock(directory, name string, fn func() error) error {
	unlock, err := lockPathExclusive(directory, name, "resource", true)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
