//go:build linux

package engine

import (
	"os"
	"syscall"
	"testing"
)

type serverOwnerTestFileInfo struct {
	os.FileInfo
	status syscall.Stat_t
}

func (info serverOwnerTestFileInfo) Sys() any {
	return &info.status
}

func TestProductionServerOwnerValidatorsDistinguishRootAndRootGroup(t *testing.T) {
	rootInfo, err := os.Stat("/")
	if err != nil {
		t.Fatalf("Stat(/): %v", err)
	}
	rootStatus, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("root FileInfo has no Linux Stat_t")
	}
	root := serverOwnerTestFileInfo{FileInfo: rootInfo, status: *rootStatus}
	root.status.Uid = 0
	root.status.Gid = 0
	if err := requireProductionRootOwner("/", root); err != nil {
		t.Fatalf("requireProductionRootOwner(root:root): %v", err)
	}
	if err := requireProductionRootGroupOwner("/", root); err != nil {
		t.Fatalf("requireProductionRootGroupOwner(root:root): %v", err)
	}

	rootNonrootGroup := root
	rootNonrootGroup.status.Gid = 1
	if err := requireProductionRootOwner("/", rootNonrootGroup); err != nil {
		t.Fatalf("root owner validator unexpectedly required root group: %v", err)
	}
	if err := requireProductionRootGroupOwner("/", rootNonrootGroup); err == nil {
		t.Fatal("root:root owner validator accepted a non-root group")
	}

	nonroot := root
	nonroot.status.Uid = 1
	if err := requireProductionRootOwner("/", nonroot); err == nil {
		t.Fatal("root owner validator accepted a non-root UID")
	}
	if err := requireProductionRootGroupOwner("/", nonroot); err == nil {
		t.Fatal("root:root owner validator accepted a non-root UID")
	}
}
