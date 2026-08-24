package release_test

import (
	"os"
	"os/exec"
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
	checklist, err := releaseevidence.LoadChecklistV3(releaseevidence.DefaultChecklistV3Path(root))
	if err != nil {
		t.Fatalf("LoadChecklistV3: %v", err)
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
	schemaPath := filepath.Join(root, "schemas", "release-evidence-v3.schema.json")
	schema := string(readFile(t, schemaPath))
	for _, required := range []string{
		`"const": "warptweet.release-evidence"`,
		`"package_to_package"`,
		`"source_tree_substitution"`,
		`"client_package_sha256"`,
		`"server_package_sha256"`,
		`"contract_id"`,
		`"host_target"`,
		`"published_endpoint_generation"`,
		`"test_dnat_absent"`,
		`"enrollment_resolved_addr"`,
	} {
		if !strings.Contains(schema, required) {
			t.Errorf("schema omits %q", required)
		}
	}
	v2 := string(readFile(t, filepath.Join(root, "schemas", "release-evidence-v2.schema.json")))
	if !strings.Contains(v2, `"additionalProperties": false`) {
		t.Error("v2 schema must keep additionalProperties false")
	}
	if strings.Contains(v2, `"test_dnat_absent"`) {
		t.Error("v2 schema must not grow networking fields")
	}
	if len(releaseevidence.RequiredMatrixCells(checklist.Checklist())) != 4 {
		t.Fatal("v3 public index must keep the four-cell architecture matrix")
	}
}

func TestInteropListenIsBindAdvertiseIsExplicit(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	files := []string{
		filepath.Join(root, "scripts", "interop", "lib", "common.sh"),
		filepath.Join(root, "scripts", "interop", "dev-run.sh"),
		filepath.Join(root, "scripts", "interop", "lib", "cases.sh"),
		filepath.Join(root, "scripts", "interop", "orchestrate.sh"),
		filepath.Join(root, "scripts", "interop", "config.example.env"),
	}
	for _, path := range files {
		contents := string(readFile(t, path))
		for _, forbidden := range []string{
			"WARPTWEET_INTEROP_SERVER_ADVERTISE=\"${WARPTWEET_INTEROP_SERVER_LISTEN}\"",
			"WARPTWEET_INTEROP_SERVER_ADVERTISE=$WARPTWEET_INTEROP_SERVER_LISTEN",
			"WARPTWEET_INTEROP_SERVER_ADVERTISE=${WARPTWEET_INTEROP_SERVER_LISTEN}",
			"wt-gcp-bind",
			"iptables -t nat -A",
			"iptables -t nat -I",
			"DNAT --to-destination",
			"ip addr add",
		} {
			if strings.Contains(contents, forbidden) {
				t.Errorf("%s contains forbidden %q", path, forbidden)
			}
		}
	}
	common := string(readFile(t, filepath.Join(root, "scripts", "interop", "lib", "common.sh")))
	for _, required := range []string{
		"interop_host_publication_args",
		"interop_published_data_dial",
		"Pass --advertise only when",
	} {
		if !strings.Contains(common, required) {
			t.Errorf("common.sh omits %q", required)
		}
	}
	if !strings.Contains(common, "Never default ADVERTISE=LISTEN") &&
		!strings.Contains(common, "never default ADVERTISE=LISTEN") {
		t.Error("common.sh must state that ADVERTISE is never defaulted to LISTEN")
	}
	evidence := string(readFile(t, filepath.Join(root, "scripts", "interop", "lib", "evidence.sh")))
	for _, forbidden := range []string{
		`as_bool("WARPTWEET_INTEROP_LISTENERS_MATCH_BINDS", "true")`,
		`as_bool("WARPTWEET_INTEROP_TEST_DNAT_ABSENT", "true")`,
		`as_bool("WARPTWEET_INTEROP_LOOPBACK_ALIAS_ABSENT", "true")`,
		`as_bool("WARPTWEET_INTEROP_INVITE_DIALS_MATCH", "true")`,
		"interop_fill_networking_defaults || true",
	} {
		if strings.Contains(evidence, forbidden) {
			t.Errorf("evidence.sh defaults an observation fail-open: %s", forbidden)
		}
	}
	for _, required := range []string{
		"gce-one-to-one-nat",
		"publication_dnat.py",
		"live_table_status",
		"IPTABLES=",
		"require_bool",
		"invite schema is not 3",
	} {
		if !strings.Contains(evidence, required) {
			t.Errorf("evidence.sh omits %q", required)
		}
	}
}

func TestPublicationDNATClassifierIgnoresDockerPostgres(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	path := filepath.Join(root, "scripts", "interop", "lib", "publication_dnat.py")
	cmd := exec.Command("python3", path, "--self-test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("publication_dnat --self-test: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "publication_dnat_self_test_ok") {
		t.Fatalf("self-test output %q", out)
	}
}
