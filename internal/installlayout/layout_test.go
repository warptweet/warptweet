package installlayout

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFixedInstallLayoutIsAbsoluteAndContained(t *testing.T) {
	t.Parallel()

	enginePaths := []string{SSHPath, SSHKeygenPath, SSHDPath, SSHDAuthPath, SSHDSessionPath}
	for _, path := range enginePaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Errorf("engine path %q is not clean and absolute", path)
		}
		if !strings.HasPrefix(path, OpenSSHPrefix+string(filepath.Separator)) {
			t.Errorf("engine path %q escapes prefix %q", path, OpenSSHPrefix)
		}
	}
	for _, path := range []string{
		ControllerPath,
		ClientManifestPath,
		ClientIdentityDirectory,
		ClientIdentityPath,
		ClientTrustDirectory,
		ClientKnownHostsPath,
		ClientGlobalKnownHostsPath,
		ClientRuntimeRoot,
		ServerConfigPath,
		ServerManifestPath,
		ServerHostKeyPath,
		AuthorizedKeysDirectory,
		OpenSSHSourceReceiptPath,
		OpenSSLSourceReceiptPath,
		OpenSSHLicensePath,
		OpenSSLLicensePath,
		OpenSSHBundleManifestPath,
		PrivsepDirectory,
		LinuxProvisionerPath,
		LinuxProvisionerRunRoot,
		LinuxProvisionerSocket,
		GrantSessionsDirectory,
		GrantSessionSocket,
		GrantAuthorityLockPath,
		DataPlaneBootIDPath,
		DataPlaneControlSocket,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Errorf("fixed path %q is not clean and absolute", path)
		}
	}
	if ClientServiceUser == "" || ClientServiceGroup == "" {
		t.Fatal("fixed client service identity must not be empty")
	}
}

func TestDarwinInstallLayoutIsAbsoluteAndWithinSocketBudget(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		DarwinControllerPath,
		DarwinClientManifestPath,
		DarwinClientIdentityDirectory,
		DarwinClientIdentityPath,
		DarwinClientTrustDirectory,
		DarwinClientKnownHostsPath,
		DarwinClientGlobalKnownHostsPath,
		DarwinOpenSSHPrefix,
		DarwinSSHPath,
		DarwinSSHKeygenPath,
		DarwinClientRuntimeRoot,
		DarwinOpenSSHBundleManifestPath,
		DarwinProvisionerPath,
		DarwinProvisionerRunRoot,
		DarwinProvisionerSocket,
		DarwinLaunchDaemonRoot,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Errorf("darwin path %q is not clean and absolute", path)
		}
	}
	if DarwinClientServiceUser != "_warptweet" || DarwinClientServiceGroup != "_warptweet" {
		t.Fatalf("unexpected darwin service identity %q/%q", DarwinClientServiceUser, DarwinClientServiceGroup)
	}
	if len(DarwinProvisionerSocket) >= 104 {
		t.Fatalf("darwin provisioner socket path length = %d, want < 104", len(DarwinProvisionerSocket))
	}
	maximumControlPath := DarwinClientRuntimeRoot + "/" + strings.Repeat("a", 64) + "/c"
	if got := len(maximumControlPath) + 17; got > 107 {
		t.Fatalf("darwin readiness control path budget = %d, want <= 107", got)
	}
}
