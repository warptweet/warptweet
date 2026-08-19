package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWarpTweetSSHDUnitUsesBundledValidatedConfiguration(t *testing.T) {
	t.Parallel()

	unit := readUnit(t, "warptweet-sshd.service")
	requireUnitLines(t, unit,
		"Description=WarpTweet restricted post-quantum tunnel server",
		"AssertFileIsExecutable=/opt/warptweet/bin/warptweet",
		"AssertFileIsExecutable=/opt/warptweet/libexec/openssh/sbin/sshd",
		"AssertPathExists=/etc/warptweet/server.wt",
		"AssertPathExists=/etc/warptweet/sshd_config",
		"ExecStartPre=/opt/warptweet/bin/warptweet doctor-server --config /etc/warptweet/server.wt",
		"ExecStart=/opt/warptweet/libexec/openssh/sbin/sshd -D -e -f /etc/warptweet/sshd_config",
		"ExecReload=/opt/warptweet/bin/warptweet doctor-server --config /etc/warptweet/server.wt",
		"ExecReload=/bin/kill -HUP $MAINPID",
		"User=root",
		"UnsetEnvironment=LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateDevices=yes",
		"RestrictNamespaces=yes",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
	)

	for _, forbidden := range []string{
		"ExecStart=/usr/sbin/sshd",
		"ExecStart=/usr/bin/sshd",
		"ConditionFileIsExecutable=",
		"ConditionPathExists=",
		"ProtectSystem=false",
	} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("server unit contains forbidden text %q", forbidden)
		}
	}
}

func TestEnrollUnitUsesControllerEnrollmentListener(t *testing.T) {
	t.Parallel()

	unit := readUnit(t, "warptweet-enroll.service")
	requireUnitLines(t, unit,
		"Description=WarpTweet enrollment control plane",
		"AssertFileIsExecutable=/opt/warptweet/bin/warptweet",
		"AssertPathExists=/etc/warptweet/server.wt",
		"AssertPathExists=/var/lib/warptweet/ssh/ssh_host_mldsa44_ed25519_key",
		"AssertPathExists=/etc/warptweet/invite.mac-key",
		"ExecStartPre=/opt/warptweet/bin/warptweet doctor-server --config /etc/warptweet/server.wt",
		"ExecStart=/opt/warptweet/bin/warptweet server enroll-listen",
		"User=root",
		"RuntimeDirectory=warptweet/server",
		"RuntimeDirectoryMode=0750",
		"RuntimeDirectoryPreserve=yes",
		"ReadWritePaths=/var/lib/warptweet /etc/warptweet/enrollment /run/warptweet/server",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateDevices=yes",
		"RestrictNamespaces=yes",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"UnsetEnvironment=LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES",
	)

	for _, forbidden := range []string{
		"ProtectSystem=false",
		"ExecStart=/usr/bin/",
		"ConditionFileIsExecutable=",
	} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("enroll unit contains forbidden text %q", forbidden)
		}
	}
}

func TestReconcileUnitUsesTypedController(t *testing.T) {
	t.Parallel()

	unit := readUnit(t, "warptweet-reconcile.service")
	requireUnitLines(t, unit,
		"Description=WarpTweet client route reconciler",
		"AssertFileIsExecutable=/opt/warptweet/bin/warptweet",
		"Type=oneshot",
		"KillMode=process",
		"ExecStart=/opt/warptweet/bin/warptweet reconcile",
		"User=root",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
	)
}

func TestTunnelUnitUsesControllerContractWithoutAmbientPrivileges(t *testing.T) {
	t.Parallel()

	unit := readUnit(t, "warptweet-tunnel@.service")
	requireUnitLines(t, unit,
		"Description=WarpTweet managed tunnel %i",
		"AssertFileIsExecutable=/opt/warptweet/bin/warptweet",
		"AssertPathExists=/etc/warptweet/routes/%i/active.json",
		"Type=notify",
		"NotifyAccess=main",
		"ExecStart=/opt/warptweet/bin/warptweet run --route %i --once",
		"User=warptweet-client",
		"Group=warptweet-client",
		"RuntimeDirectory=warptweet/tunnels/%i",
		"RuntimeDirectoryMode=0700",
		"ReadWritePaths=/run/warptweet/tunnels/%i",
		"AmbientCapabilities=",
		"CapabilityBoundingSet=",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateDevices=yes",
		"StandardInput=null",
		"UnsetEnvironment=DISPLAY LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES SSH_ASKPASS SSH_ASKPASS_REQUIRE SSH_AUTH_SOCK",
	)

	if strings.Contains(unit, "/usr/bin/ssh") {
		t.Fatal("tunnel unit bypasses the pinned WarpTweet controller")
	}
	for _, forbidden := range []string{
		"Type=simple",
		"User=warptweet\n",
		"Group=warptweet\n",
		"--runtime-dir",
	} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("tunnel unit contains removed client boundary %q", forbidden)
		}
	}
}

func readUnit(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("..", "..", "packaging", "systemd", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func requireUnitLines(t *testing.T, unit string, lines ...string) {
	t.Helper()

	for _, line := range lines {
		if !strings.Contains(unit, line+"\n") {
			t.Errorf("unit is missing exact line %q", line)
		}
	}
}
