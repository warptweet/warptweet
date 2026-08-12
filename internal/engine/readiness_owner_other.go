//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package engine

import (
	"fmt"
	"os"
	"runtime"
)

func fileInfoOwnedByEffectiveUser(os.FileInfo) (bool, error) {
	return false, fmt.Errorf("control-socket ownership checks are unsupported on %s", runtime.GOOS)
}
