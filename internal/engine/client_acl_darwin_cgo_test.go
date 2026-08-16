//go:build darwin && cgo

package engine

import (
	"os"
	"os/exec"
	"testing"
)

func TestInspectDarwinClientFileMetadataDetectsExtendedACL(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/state"
	if err := os.WriteFile(path, []byte("state\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatalf("Stat: %v", err)
	}
	metadata, err := inspectDarwinClientFileMetadata(path, file, info)
	if err != nil {
		_ = file.Close()
		t.Fatalf("inspect without ACL: %v", err)
	}
	if metadata.hasAccessACL {
		_ = file.Close()
		t.Fatal("new file unexpectedly has an extended ACL")
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close before ACL mutation: %v", err)
	}

	if output, err := exec.Command("/bin/chmod", "+a", "everyone deny write", path).CombinedOutput(); err != nil {
		t.Fatalf("add test ACL: %v: %s", err, output)
	}
	file, err = os.Open(path)
	if err != nil {
		t.Fatalf("re-open with ACL: %v", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		t.Fatalf("stat with ACL: %v", err)
	}
	metadata, err = inspectDarwinClientFileMetadata(path, file, info)
	if err != nil {
		t.Fatalf("inspect with ACL: %v", err)
	}
	if !metadata.hasAccessACL {
		t.Fatal("extended ACL was not detected")
	}
}
