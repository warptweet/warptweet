package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxPackageBuildScriptContract(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	path := filepath.Join(root, "scripts", "build-linux-packages.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("build-linux-packages.sh is not executable")
	}
	contents := string(readFile(t, path))
	for _, required := range []string{
		`Linux package assembly requires Linux`,
		`opt/warptweet/bin/warptweet`,
		`usr/bin/warptweet`,
		`warptweet-sshd.service`,
		`warptweet-hostsign.service`,
		`warptweet-tunnel@.service`,
		`warptweet-provisioner.service`,
		`warptweet-provisioner`,
		`sshd`,
		`ssh-keygen`,
		`dpkg-deb`,
		`var/lib/warptweet/invites`,
		`Package: warptweet`,
		`dpkg-deb --root-owner-group`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("linux package script omits %q", required)
		}
	}
	for _, forbidden := range []string{
		`curl `,
		`wget `,
		`version :latest`,
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("linux package script contains forbidden %q", forbidden)
		}
	}
}

func TestLinuxPackageScriptsForbidNetwork(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	for _, relative := range []string{
		"packaging/linux/postinst.sh",
		"packaging/linux/prerm.sh",
	} {
		path := filepath.Join(root, relative)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", relative, err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s not executable", relative)
		}
		contents := string(readFile(t, path))
		for _, forbidden := range []string{"curl ", "wget ", "http://", "https://"} {
			if strings.Contains(contents, forbidden) {
				t.Errorf("%s contains %q", relative, forbidden)
			}
		}
	}
	postinst := string(readFile(t, filepath.Join(root, "packaging/linux/postinst.sh")))
	for _, required := range []string{
		`warptweet`,
		`warptweet-client`,
		`warptweet-sshd`,
		`*NP*`,
		`/var/empty/warptweet-sshd`,
		`/var/lib/warptweet/invites`,
		`usermod -L warptweet-client`,
		`usermod -L warptweet-sshd`,
		`warptweet-operator`,
		`--uid "$WT_UID"`,
		`systemctl enable --now warptweet-provisioner.service`,
		`systemctl enable warptweet-mgmt.service`,
		`install -d -o root -g warptweet-sshd -m 2750 /var/lib/warptweet/clients`,
		`find /var/lib/warptweet/clients -maxdepth 1 -type f -name '*.json'`,
		`chmod 0660 /var/lib/warptweet/sessions/grant.lock`,
		`upgrade-active.units`,
		`try-restart`,
	} {
		if !strings.Contains(postinst, required) {
			t.Errorf("postinst omits %q", required)
		}
	}
	if strings.Contains(postinst, "|| true") {
		t.Fatal("postinst discards security-boundary failures")
	}
	prerm := string(readFile(t, filepath.Join(root, "packaging/linux/prerm.sh")))
	for _, required := range []string{
		`warptweet-provisioner.service`,
		`warptweet-reconcile.service`,
		`warptweet-tunnel@`,
		`list-unit-files`,
		`stop_disable "$WT_UNIT"`,
		`remove | deconfigure | 0`,
		`upgrade-active.units`,
	} {
		if !strings.Contains(prerm, required) {
			t.Errorf("prerm omits %q", required)
		}
	}
	spec := string(readFile(t, filepath.Join(root, "scripts/build-linux-packages.sh")))
	if strings.Contains(spec, "linux-postinst.sh || true") || strings.Contains(spec, "linux-prerm.sh || true") {
		t.Fatal("RPM spec discards maintainer-script failures")
	}
	if !strings.Contains(spec, `/bin/sh /opt/warptweet/share/linux-prerm.sh "$1"`) {
		t.Fatal("RPM preun must pass the remaining-package count to prerm")
	}
	enrollmentUnit := string(readFile(t, filepath.Join(root, "packaging/systemd/warptweet-enroll.service")))
	for _, required := range []string{
		`ReadWritePaths=/var/lib/warptweet /etc/warptweet/enrollment /run/warptweet/server`,
		`ExecStart=/opt/warptweet/bin/warptweet server enroll-listen`,
	} {
		if !strings.Contains(enrollmentUnit, required) {
			t.Errorf("enrollment unit omits %q", required)
		}
	}
}
