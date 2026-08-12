//go:build !linux

package engine

import (
	"errors"
	"os"
)

func requireProductionRootOwner(_ string, _ os.FileInfo) error {
	return errors.New("production server ownership validation requires Linux")
}

func requireProductionRootGroupOwner(_ string, _ os.FileInfo) error {
	return errors.New("production server root:root ownership validation requires Linux")
}
