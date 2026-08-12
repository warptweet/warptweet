//go:build !linux && !darwin

package engine

import (
	"errors"
	"os"
)

type unsupportedExecutableInspector struct{}

func productionExecutableInspector() executableInspector {
	return unsupportedExecutableInspector{}
}

func (unsupportedExecutableInspector) Inspect(*os.File) (executableLinkageReport, error) {
	return executableLinkageReport{}, errors.New("production OpenSSH executable inspection requires Linux or Darwin")
}
