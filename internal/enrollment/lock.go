package enrollment

// WithExclusiveLock runs fn while holding a cross-process exclusive lock named
// under directory. Unlock always runs, including when fn returns an error.
func WithExclusiveLock(directory, name string, fn func() error) error {
	unlock, err := lockPathExclusive(directory, name, "resource")
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
