package main

import (
	"fmt"
	"os"
	"path/filepath"

	"warptweet.com/warptweet/internal/publicrelease"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-public-release: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stat(filepath.Join(root, "packaging", "evidence", "public-release.json")); err != nil {
		fmt.Fprintf(os.Stderr, "verify-public-release: run from the repository root\n")
		os.Exit(1)
	}
	if err := publicrelease.VerifyRepository(root); err != nil {
		fmt.Fprintf(os.Stderr, "verify-public-release: %v\n", err)
		os.Exit(1)
	}
}
