//go:build !linux && !darwin

package engine

import (
	"errors"
	"os"
)

func fileInfoOwnedByRoot(os.FileInfo) (bool, error) {
	return false, errors.New("root ownership validation requires Linux or Darwin")
}
