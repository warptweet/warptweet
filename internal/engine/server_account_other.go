//go:build !linux

package engine

import "errors"

func inspectProductionServerAccounts(_ string) (serverAccountEvidence, error) {
	return serverAccountEvidence{}, errors.New("production server account validation requires Linux")
}
