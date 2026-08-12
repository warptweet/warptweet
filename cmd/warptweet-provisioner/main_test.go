package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestProvisionerRejectsArbitraryRequests(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "warptweet-provisioner") {
		t.Fatalf("version output=%q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"exec", "/bin/sh"}, &stdout, &stderr); code == 0 {
		t.Fatal("accepted arbitrary request")
	}
	if !strings.Contains(stderr.String(), "unknown request") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestVerifyLayoutRequiresRoot(t *testing.T) {
	t.Parallel()

	if osGeteuid() == 0 {
		t.Skip("running as root")
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"verify-layout"}, &stdout, &stderr); code == 0 {
		t.Fatal("verify-layout succeeded without root")
	}
	if !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

// osGeteuid wraps os.Geteuid for tests without importing os into every assertion.
func osGeteuid() int {
	return geteuid()
}
