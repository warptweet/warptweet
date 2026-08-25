package command

import (
	"path/filepath"
	"testing"
)

func TestLoadHostRevisionRejectsMismatchedEnvelope(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "applied-receipt.json")
	rev := hostRevision{
		Kind:           "warptweet.host-applied-receipt-other",
		SchemaVersion:  hostRevisionVer,
		NetworkSHA256:  "aa",
		CertLeafSHA256: "bb",
	}
	if err := writeHostRevision(path, rev); err != nil {
		t.Fatal(err)
	}
	if loaded, ok, err := loadHostRevision(path, hostAppliedKind); err != nil || ok {
		t.Fatalf("mismatched kind ok=%v err=%v loaded=%+v", ok, err, loaded)
	}

	rev.Kind = hostAppliedKind
	rev.SchemaVersion = hostRevisionVer + 1
	if err := writeHostRevision(path, rev); err != nil {
		t.Fatal(err)
	}
	if loaded, ok, err := loadHostRevision(path, hostAppliedKind); err != nil || ok {
		t.Fatalf("mismatched schema ok=%v err=%v loaded=%+v", ok, err, loaded)
	}

	rev.SchemaVersion = hostRevisionVer
	if err := writeHostRevision(path, rev); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := loadHostRevision(path, hostAppliedKind)
	if err != nil || !ok {
		t.Fatalf("valid receipt ok=%v err=%v", ok, err)
	}
	if loaded.NetworkSHA256 != "aa" || loaded.CertLeafSHA256 != "bb" {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestHostRevisionEqualRequiresSchemaVersion(t *testing.T) {
	t.Parallel()

	left := hostRevision{SchemaVersion: hostRevisionVer, NetworkSHA256: "aa", CertLeafSHA256: "bb"}
	right := left
	if !left.equal(right) {
		t.Fatal("identical revisions compared unequal")
	}
	right.SchemaVersion = hostRevisionVer + 1
	if left.equal(right) {
		t.Fatal("schema version was ignored")
	}
}
