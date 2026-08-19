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
		`warptweet-tunnel@.service`,
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
	} {
		if !strings.Contains(postinst, required) {
			t.Errorf("postinst omits %q", required)
		}
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
