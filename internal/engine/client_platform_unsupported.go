//go:build !linux && !darwin

package engine

import "errors"

func requireProductionClientPlatform() error {
	return errors.New("production OpenSSH client preflight requires Linux or Darwin")
}
