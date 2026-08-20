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

func TestDualHostInteropUsesInstalledProvisionerWithoutClientElevation(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	common := string(readFile(t, filepath.Join(root, "scripts", "interop", "lib", "common.sh")))
	packages := string(readFile(t, filepath.Join(root, "scripts", "interop", "lib", "package.sh")))
	configuration := string(readFile(t, filepath.Join(root, "scripts", "interop", "config.example.env")))

	if !strings.Contains(common, `"$WARPTWEET_INTEROP_CLIENT_CTRL" "$@"`) {
		t.Error("interop common.sh omits the client controller invocation")
	}
	if !strings.Contains(configuration, `/Library/Application Support/WarpTweet/bin/warptweet`) {
		t.Error("interop config.example.env omits the installed controller path")
	}
	for _, required := range []string{
		`/var/run/warptweet/provisioner.sock`,
		`dscl . -read /Groups/admin PrimaryGroupID`,
		`"0:$_admin_gid:660"`,
	} {
		if !strings.Contains(packages, required) {
			t.Errorf("interop package verification omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"interop_ensure_client_state_writable",
		"dseditgroup -o edit -a",
		"chown -R \"$_user\":_warptweet",
		"do shell script cmd with administrator privileges",
	} {
		if strings.Contains(common, forbidden) || strings.Contains(packages, forbidden) {
			t.Errorf("interop retains privileged client workaround %q", forbidden)
		}
	}
}

func TestReleaseEvidenceChecklistMatchesHomebrewDelivery(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	checklist, err := releaseevidence.LoadChecklistV2(releaseevidence.DefaultChecklistV2Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV2: %v", err)
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
		"second-client-grant",
		"two-independent-routes",
		"reboot-unless-stopped-manual-down",
		"live-expiry-and-revocation",
		"clock-rollback-fail-closed",
		"target-change-denial",
		"compose-loopback-postgres",
		"agent-skill-delivery",
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
		"pid-reuse-and-stop-failure",
		"silent-renewal-and-port-reassignment",
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
	schemaPath := filepath.Join(root, "schemas", "release-evidence-v2.schema.json")
	schema := string(readFile(t, schemaPath))
	for _, required := range []string{
		`"const": "warptweet.release-evidence"`,
		`"package_to_package"`,
		`"source_tree_substitution"`,
		`"client_package_sha256"`,
		`"server_package_sha256"`,
		`"contract_id"`,
		`"host_target"`,
	} {
		if !strings.Contains(schema, required) {
			t.Errorf("schema omits %q", required)
		}
	}
}
