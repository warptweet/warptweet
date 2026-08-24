package release_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
		"DEBIAN/md5sums",
		"md5sum ",
	} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("linux package script contains forbidden %q", forbidden)
		}
	}
	if !strings.Contains(contents, "MD5 is not an integrity algorithm here") {
		t.Error("linux package script must record why Debian md5sums members are omitted")
	}

	payload := []byte("warptweet-linux-package-fixture\n")
	bundle := sha256sumRecord(payload, "opt/warptweet/share/payload")
	inspectDebControlAndData(t, writeArDebFixture(t, payload, bundle), bundle)
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		return
	}
	inspectDebControlAndData(t, writeDpkgDebFixture(t, payload, bundle), bundle)
}

func TestSignLinuxDebRecordsSHA256(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	script := filepath.Join(root, "scripts", "sign-linux-deb.sh")
	contents := string(readFile(t, script))
	for _, required := range []string{
		`file_sha256()`,
		`echo "SHA256:"`,
		`--armor --detach-sign --output "$WT_DEB.asc"`,
		`dpkg-sig Version 4 still lists MD5 and SHA-1`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("sign-linux-deb.sh omits %q", required)
		}
	}

	if runtime.GOOS == "windows" {
		t.Skip("POSIX package signing is Unix-only")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is required to exercise sign-linux-deb.sh")
	}
	if _, err := exec.LookPath("ar"); err != nil {
		t.Skip("ar is required to exercise sign-linux-deb.sh")
	}

	payload := []byte("warptweet-linux-sign-fixture\n")
	bundle := sha256sumRecord(payload, "opt/warptweet/share/payload")
	deb := writeArDebFixture(t, payload, bundle)
	fingerprint, gpgHome := newEphemeralSigningKey(t)
	command := exec.Command("sh", script, deb)
	command.Env = append(
		envWithout("WARPTWEET_LINUX_GPG_KEY", "GNUPGHOME", "PATH"),
		"PATH="+isolatedUnixPath(t),
		"GNUPGHOME="+gpgHome,
		"WARPTWEET_LINUX_GPG_KEY="+fingerprint,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("sign-linux-deb.sh: %v\n%s", err, output)
	}

	members := arMembers(t, deb)
	debianBinary := arExtract(t, deb, "debian-binary")
	controlMember := arMemberPrefix(t, members, "control.tar")
	dataMember := arMemberPrefix(t, members, "data.tar")
	control := arExtract(t, deb, controlMember)
	data := arExtract(t, deb, dataMember)
	builder := arExtract(t, deb, "_gpgbuilder")
	if !bytes.Contains(builder, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		t.Fatal("_gpgbuilder is not a clearsigned document")
	}
	recorded := parseSHA256Section(t, string(builder))
	for _, item := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", debianBinary},
		{controlMember, control},
		{dataMember, data},
	} {
		sum := sha256.Sum256(item.body)
		got, ok := recorded[item.name]
		if !ok {
			t.Fatalf("SHA256 section omits %q", item.name)
		}
		if got.hash != hex.EncodeToString(sum[:]) {
			t.Errorf("%s SHA256 = %s, want %s", item.name, got.hash, hex.EncodeToString(sum[:]))
		}
		if got.size != int64(len(item.body)) {
			t.Errorf("%s size = %d, want %d", item.name, got.size, len(item.body))
		}
	}

	asc := deb + ".asc"
	armored := readFile(t, asc)
	if !bytes.HasPrefix(bytes.TrimSpace(armored), []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatal("detached signature is not armored PGP SIGNATURE")
	}
	if bytes.Contains(armored, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		t.Fatal("detached .asc must not be a clearsigned document")
	}
	verify := exec.Command("gpg", "--batch", "--verify", asc, deb)
	verify.Env = append(envWithout("GNUPGHOME"), "GNUPGHOME="+gpgHome)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("gpg --verify .asc: %v\n%s", err, output)
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

func sha256sumRecord(payload []byte, relative string) []byte {
	sum := sha256.Sum256(payload)
	return []byte(hex.EncodeToString(sum[:]) + "  " + relative + "\n")
}

func writeTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, body := range files {
		header := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("tar header %q: %v", name, err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatalf("tar write %q: %v", name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buffer.Bytes()
}

func writeArDebFixture(t *testing.T, payload, bundle []byte) string {
	t.Helper()

	if _, err := exec.LookPath("ar"); err != nil {
		t.Skip("ar is required to assemble a fixture .deb")
	}
	directory := t.TempDir()
	control := writeTarGz(t, map[string][]byte{
		"control": []byte("Package: warptweet\nVersion: 0.0.0-test\nArchitecture: all\nMaintainer: WarpTweet Tests\nDescription: fixture\n"),
	})
	data := writeTarGz(t, map[string][]byte{
		"opt/warptweet/share/payload":               payload,
		"opt/warptweet/share/openssh-bundle.sha256": bundle,
	})
	writeFile(t, filepath.Join(directory, "debian-binary"), []byte("2.0\n"))
	writeFile(t, filepath.Join(directory, "control.tar.gz"), control)
	writeFile(t, filepath.Join(directory, "data.tar.gz"), data)
	deb := filepath.Join(directory, "warptweet_0.0.0-test_all.deb")
	command := exec.Command("ar", "-qc", deb, "debian-binary", "control.tar.gz", "data.tar.gz")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ar: %v\n%s", err, output)
	}
	return deb
}

func writeDpkgDebFixture(t *testing.T, payload, bundle []byte) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), "deb")
	for _, directory := range []string{
		filepath.Join(root, "DEBIAN"),
		filepath.Join(root, "opt", "warptweet", "share"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	writeFile(t, filepath.Join(root, "DEBIAN", "control"), []byte("Package: warptweet\nVersion: 0.0.0-test\nArchitecture: all\nMaintainer: WarpTweet Tests\nDescription: fixture\n"))
	writeFile(t, filepath.Join(root, "opt", "warptweet", "share", "payload"), payload)
	writeFile(t, filepath.Join(root, "opt", "warptweet", "share", "openssh-bundle.sha256"), bundle)
	deb := filepath.Join(t.TempDir(), "warptweet_0.0.0-test_all.deb")
	command := exec.Command("dpkg-deb", "--root-owner-group", "-Zgzip", "--build", root, deb)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb: %v\n%s", err, output)
	}
	return deb
}

func inspectDebControlAndData(t *testing.T, deb string, wantBundle []byte) {
	t.Helper()

	members := arMembers(t, deb)
	controlMember := arMemberPrefix(t, members, "control.tar")
	dataMember := arMemberPrefix(t, members, "data.tar")
	controlFiles := tarFiles(t, arExtract(t, deb, controlMember), controlMember)
	for name := range controlFiles {
		base := filepath.Base(strings.TrimPrefix(name, "./"))
		if base == "md5sums" || strings.EqualFold(base, "md5sum") {
			t.Errorf("control archive contains %q", name)
		}
	}
	dataFiles := tarFiles(t, arExtract(t, deb, dataMember), dataMember)
	got, ok := dataFiles["opt/warptweet/share/openssh-bundle.sha256"]
	if !ok {
		t.Fatal("data archive omits opt/warptweet/share/openssh-bundle.sha256")
	}
	if !bytes.Equal(got, wantBundle) {
		t.Fatalf("openssh-bundle.sha256 = %q, want %q", got, wantBundle)
	}
	payload, ok := dataFiles["opt/warptweet/share/payload"]
	if !ok {
		t.Fatal("data archive omits payload")
	}
	sum := sha256.Sum256(payload)
	wantLine := hex.EncodeToString(sum[:]) + "  opt/warptweet/share/payload\n"
	if string(got) != wantLine {
		t.Fatalf("bundle record %q does not hash payload", got)
	}
}

func arMembers(t *testing.T, deb string) []string {
	t.Helper()

	command := exec.Command("ar", "t", deb)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("ar t: %v\n%s", err, output)
	}
	var members []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			members = append(members, line)
		}
	}
	if len(members) == 0 {
		t.Fatal("deb has no ar members")
	}
	return members
}

func arMemberPrefix(t *testing.T, members []string, prefix string) string {
	t.Helper()

	for _, member := range members {
		if strings.HasPrefix(member, prefix) {
			return member
		}
	}
	t.Fatalf("deb omits member prefix %q in %q", prefix, members)
	return ""
}

func arExtract(t *testing.T, deb, member string) []byte {
	t.Helper()

	command := exec.Command("ar", "p", deb, member)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("ar p %s: %v", member, err)
	}
	return output
}

func tarFiles(t *testing.T, raw []byte, member string) map[string][]byte {
	t.Helper()

	var reader io.Reader = bytes.NewReader(raw)
	switch {
	case strings.Contains(member, ".tar.gz") || strings.HasSuffix(member, ".tgz"):
		gzipReader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("gzip %s: %v", member, err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	case strings.Contains(member, ".tar.xz"):
		reader = decompressTool(t, "xz", raw)
	case strings.Contains(member, ".tar.zst"):
		reader = decompressTool(t, "zstd", raw)
	}
	archive := tar.NewReader(reader)
	files := map[string][]byte{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar %s: %v", member, err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatalf("tar read %s: %v", header.Name, err)
		}
		files[strings.TrimPrefix(header.Name, "./")] = body
	}
	return files
}

func decompressTool(t *testing.T, name string, raw []byte) io.Reader {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is required to inspect %s-compressed deb members", name, name)
	}
	args := []string{"-dc"}
	if name == "zstd" {
		args = []string{"-d", "-c"}
	}
	command := exec.Command(path, args...)
	command.Stdin = bytes.NewReader(raw)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return bytes.NewReader(output)
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()

	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func envWithout(keys ...string) []string {
	drop := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		drop[key] = struct{}{}
	}
	var environment []string
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, skip := drop[key]; skip {
			continue
		}
		environment = append(environment, item)
	}
	return environment
}

func isolatedUnixPath(t *testing.T) string {
	t.Helper()

	bin := t.TempDir()
	for _, name := range []string{
		"gpg", "gpg-agent", "gpgconf", "ar", "awk", "wc", "tr", "date",
		"mktemp", "rm", "cat", "shasum", "sha256sum", "sha1sum", "md5sum",
		"md5", "uname", "sh", "bash",
	} {
		resolved, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.Symlink(resolved, filepath.Join(bin, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	return bin
}

func newEphemeralSigningKey(t *testing.T) (fingerprint, home string) {
	t.Helper()

	home, err := os.MkdirTemp("/tmp", "wt-gpg-")
	if err != nil {
		t.Fatalf("gpg home: %v", err)
	}
	t.Cleanup(func() {
		kill := exec.Command("gpgconf", "--kill", "gpg-agent")
		kill.Env = append(envWithout("GNUPGHOME"), "GNUPGHOME="+home)
		_ = kill.Run()
		_ = os.RemoveAll(home)
	})
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod gpg home: %v", err)
	}
	generate := exec.Command(
		"gpg",
		"--batch",
		"--passphrase", "",
		"--pinentry-mode", "loopback",
		"--quick-generate-key",
		"WarpTweet Test <wt-test@example.invalid>",
		"ed25519",
		"sign",
		"never",
	)
	generate.Env = append(envWithout("GNUPGHOME"), "GNUPGHOME="+home)
	if output, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("gpg --quick-generate-key: %v\n%s", err, output)
	}
	list := exec.Command("gpg", "--batch", "--list-secret-keys", "--with-colons")
	list.Env = append(envWithout("GNUPGHOME"), "GNUPGHOME="+home)
	output, err := list.Output()
	if err != nil {
		t.Fatalf("gpg --list-secret-keys: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.HasPrefix(line, "fpr:") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[9] != "" {
			return fields[9], home
		}
	}
	t.Fatal("gpg did not print a fingerprint")
	return "", home
}

type sha256Member struct {
	hash string
	size int64
}

func parseSHA256Section(t *testing.T, body string) map[string]sha256Member {
	t.Helper()

	marker := "\nSHA256:\n"
	index := strings.Index(body, marker)
	if index < 0 {
		t.Fatal("_gpgbuilder omits SHA256 section")
	}
	rest := body[index+len(marker):]
	if end := strings.Index(rest, "-----BEGIN"); end >= 0 {
		rest = rest[:end]
	}
	recorded := map[string]sha256Member{}
	for _, line := range strings.Split(rest, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("SHA256 line %q", line)
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("SHA256 size %q: %v", fields[1], err)
		}
		recorded[fields[2]] = sha256Member{hash: fields[0], size: size}
	}
	if len(recorded) != 3 {
		t.Fatalf("SHA256 section has %d members, want 3", len(recorded))
	}
	return recorded
}
