//go:build !linux && !darwin

package command

func requireServiceManagedRun() error {
	return managedRunUnauthorized()
}
