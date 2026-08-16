//go:build darwin && !cgo

package engine

import (
	"errors"
	"os"
)

func darwinFileHasExtendedACL(_ *os.File) (bool, error) {
	return false, errors.New("Darwin client ACL inspection requires cgo")
}
