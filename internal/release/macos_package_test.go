package release_test

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMacOSPackageUsesTypedProvisionerAndDedicatedTunnelJobs(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	build := string(readFile(t, filepath.Join(root, "scripts", "build-macos-pkg.sh")))
	preinstall := string(readFile(t, filepath.Join(root, "packaging", "macos", "scripts", "preinstall")))
	postinstall := string(readFile(t, filepath.Join(root, "packaging", "macos", "scripts", "postinstall")))
	uninstall := string(readFile(t, filepath.Join(root, "packaging", "macos", "scripts", "uninstall.sh")))
	plistPath := filepath.Join(root, "packaging", "macos", "launchd", "com.warptweet.provisioner.plist")
	plist := readFile(t, plistPath)

	type plistDocument struct {
		XMLName xml.Name  `xml:"plist"`
		Dict    *struct{} `xml:"dict"`
	}
	var document plistDocument
	if err := xml.Unmarshal(plist, &document); err != nil {
		t.Fatalf("parse provisioner plist: %v", err)
	}
	if document.XMLName.Local != "plist" || document.Dict == nil {
		t.Fatalf("parse provisioner plist: root must be plist with dict child, got %q dict=%v", document.XMLName.Local, document.Dict != nil)
	}
	for _, required := range []string{
		"com.warptweet.provisioner",
		"/Library/Application Support/WarpTweet/bin/warptweet-provisioner",
		"<string>serve</string>",
		"<key>UserName</key>",
		"<string>root</string>",
	} {
		if !strings.Contains(string(plist), required) {
			t.Errorf("provisioner plist omits %q", required)
		}
	}
	for _, required := range []string{
		`install -m 0755 "$WT_PROVISIONER"`,
		`com.warptweet.provisioner.plist`,
		`WARPTWEET_REQUIRE_SIGNED_PKG`,
	} {
		if !strings.Contains(build, required) {
			t.Errorf("macOS package build omits %q", required)
		}
	}
	if strings.Contains(build, "com.warptweet.client.plist") {
		t.Fatal("macOS package still installs the obsolete static client LaunchDaemon")
	}

	for _, required := range []string{
		`launchctl bootout "system/$WT_LABEL"`,
		`launchctl bootout system/com.warptweet.provisioner`,
	} {
		if !strings.Contains(preinstall, required) {
			t.Errorf("preinstall omits bounded service stop %q", required)
		}
	}
	for _, required := range []string{
		`verify_service_identity`,
		`WarpTweet service UID or GID is reused by another account`,
		`WarpTweet service group must not list supplementary members`,
		`dscl . -delete "/Users/$WT_USER" AuthenticationAuthority`,
		`WT_ADMIN_GROUP_ID=$(dscl . -read /Groups/admin PrimaryGroupID`,
		`chmod -N "$WT_ACL_PATH"`,
		`chmod -RN "$WT_STATE"`,
		`launchctl bootstrap system "$WT_PROVISIONER_PLIST"`,
		`WT_SOCKET_STATE=$(stat -f '%u:%g:%Lp' "$WT_SOCKET")`,
		`"0:$WT_ADMIN_GROUP_ID:660"`,
	} {
		if !strings.Contains(postinstall, required) {
			t.Errorf("postinstall omits %q", required)
		}
	}
	if strings.Contains(uninstall, "pkill") || strings.Contains(uninstall, "killall") {
		t.Fatal("uninstall contains an unbound process-name kill")
	}
	for _, required := range []string{
		`/Library/LaunchDaemons/com.warptweet.tunnel.*.plist`,
		`launchctl bootout "system/$WT_LABEL"`,
		`launchctl bootout system/com.warptweet.provisioner`,
	} {
		if !strings.Contains(uninstall, required) {
			t.Errorf("uninstall omits %q", required)
		}
	}

	for _, script := range []string{preinstall, postinstall, uninstall} {
		if strings.Contains(script, "curl ") || strings.Contains(script, "wget ") {
			t.Fatal("macOS installer script unexpectedly contacts the network")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "packaging", "macos", "launchd", "com.warptweet.client.plist")); !os.IsNotExist(err) {
		t.Fatalf("obsolete static client plist still exists: %v", err)
	}
}
