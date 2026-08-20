package release_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardOnlyOpenSSHIsAppliedAfterUpstreamTests(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	build := string(readFile(t, filepath.Join(root, "scripts", "build-openssh.sh")))
	applyGrant := strings.Index(build, `apply-openssh-grant-hook.sh`)
	applyForward := strings.Index(build, `apply-openssh-forward-only.sh`)
	makeTests := strings.Index(build, `LC_ALL=C make tests`)
	rebuild := strings.Index(build, `make -j "$WT_BUILD_JOBS" sshd sshd-session`)
	if makeTests == -1 || applyGrant == -1 || applyForward == -1 || rebuild == -1 {
		t.Fatal("build-openssh.sh missing forward-only sequence")
	}
	if !(makeTests < applyForward && applyGrant < applyForward && applyForward < rebuild) {
		t.Fatal("forward-only patch must run after upstream tests and before sshd-session rebuild")
	}
	if !strings.Contains(build, "unused helper") {
		t.Fatal("Linux stage must refuse unused OpenSSH helpers")
	}

	remote := string(readFile(t, filepath.Join(root, "scripts", "build-linux-rc-remote.sh")))
	if !strings.Contains(remote, "apply-openssh-forward-only.sh") {
		t.Fatal("remote RC stage manifest omits forward-only apply script")
	}
}

func TestApplyOpenSSHForwardOnlyRewritesServerloop(t *testing.T) {
	if testing.Short() {
		t.Skip("uses sh")
	}
	t.Parallel()

	root := repositoryRoot(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "serverloop.c")
	original := `static int
server_input_channel_open(int type, uint32_t seq, struct ssh *ssh)
{
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, rchan, rwindow, rmaxpack);

	if (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} else if (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	}

	debug_f("rtype %s want_reply %d", rtype, want_reply);

	if (strcmp(rtype, "tcpip-forward") == 0) {
		success = 1;
	}
}

static int
server_input_global_request(int type, uint32_t seq, struct ssh *ssh)
{
	return 0;
}
`
	if err := os.WriteFile(source, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(root, "scripts", "apply-openssh-forward-only.sh"), dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("apply: %v\n%s", err, output)
	}
	rewritten := string(readFile(t, source))
	if !strings.Contains(rewritten, "WarpTweet allows only direct-tcpip channels") {
		t.Fatal("channel open was not restricted")
	}
	if !strings.Contains(rewritten, "WarpTweet refused SSH global request") {
		t.Fatal("global requests were not restricted")
	}
	cmd = exec.Command("sh", filepath.Join(root, "scripts", "apply-openssh-forward-only.sh"), dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("idempotent apply: %v\n%s", err, output)
	}
}
