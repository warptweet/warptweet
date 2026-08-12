package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/releaseevidence"
)

func TestPackageInteropScriptContract(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	path := filepath.Join(root, "scripts", "test-package-interop.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("test-package-interop.sh is not executable")
	}
	contents := string(readFile(t, path))
	for _, required := range []string{
		`WARPTWEET_CI_PACKAGE_INTEROP=1`,
		`package_to_package`,
		`source_tree_substitution`,
		`source-tree substitution is forbidden`,
		`pkg-signature-and-manifest`,
		`invite-enroll-single-use`,
		`classical-only-kex-host-client`,
		`not_run`,
		`evidence document contains fail or not_run`,
		`WARPTWEET_CLIENT_PACKAGE_SHA256`,
		`WARPTWEET_SERVER_PACKAGE_SHA256`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("interop script omits %q", required)
		}
	}
	for _, forbidden := range []string{
		`WARPTWEET_ALLOW_SOURCE_TREE=1 is required`,
		`curl `,
		`wget `,
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("interop script contains forbidden %q", forbidden)
		}
	}
}

func TestReleaseEvidenceChecklistMatchesHomebrewDelivery(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklist(releaseevidence.DefaultChecklistPath(root))
	if err != nil {
		t.Fatalf("LoadChecklist: %v", err)
	}
	requiredPositive := []string{
		"pkg-signature-and-manifest",
		"engine-identity-trust-preflight",
		"invite-enroll-single-use",
		"composite-auth",
		"exact-kex-aead",
		"rekey-same-profile",
		"pid-bound-readiness",
		"deterministic-target-payload",
		"stop-restart-rotate-revoke-upgrade",
	}
	requiredNegative := []string{
		"classical-only-kex-host-client",
		"wrong-host-pin",
		"malformed-keys-messages",
		"invite-fail-closed",
		"forwarding-surface-rejected",
		"local-state-mutation",
		"engine-and-package-tamper",
		"bounded-floods",
		"availability-faults",
	}
	have := map[string]string{}
	for _, item := range checklist.Positive {
		have[item.ID] = "positive"
	}
	for _, item := range checklist.Negative {
		have[item.ID] = "negative"
	}
	for _, id := range requiredPositive {
		if have[id] != "positive" {
			t.Errorf("missing positive case %q", id)
		}
	}
	for _, id := range requiredNegative {
		if have[id] != "negative" {
			t.Errorf("missing negative case %q", id)
		}
	}
	schemaPath := filepath.Join(root, "schemas", "release-evidence-v1.schema.json")
	schema := string(readFile(t, schemaPath))
	for _, required := range []string{
		`"const": "warptweet.release-evidence"`,
		`"package_to_package"`,
		`"source_tree_substitution"`,
		`"client_package_sha256"`,
		`"server_package_sha256"`,
	} {
		if !strings.Contains(schema, required) {
			t.Errorf("schema omits %q", required)
		}
	}
}
