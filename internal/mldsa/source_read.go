package mldsa

import (
	"os"
	"path/filepath"
	"runtime"
)

func readSOURCE() ([]byte, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return os.ReadFile("SOURCE")
	}
	return os.ReadFile(filepath.Join(filepath.Dir(file), "SOURCE"))
}
