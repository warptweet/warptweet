//go:build darwin

package provisioner

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderTunnelPlistIsClosedAndDeterministic(t *testing.T) {
	t.Parallel()

	first, label, err := renderTunnelPlist("db-1", false, true)
	if err != nil {
		t.Fatalf("renderTunnelPlist: %v", err)
	}
	second, secondLabel, err := renderTunnelPlist("db-1", false, true)
	if err != nil {
		t.Fatalf("renderTunnelPlist repeat: %v", err)
	}
	if label != "com.warptweet.tunnel.db-1" || secondLabel != label || !bytes.Equal(first, second) {
		t.Fatalf("nondeterministic plist or label %q/%q", label, secondLabel)
	}
	text := string(first)
	for _, required := range []string{
		"<string>/Library/Application Support/WarpTweet/bin/warptweet</string>",
		"<string>run</string>",
		"<string>--managed-lifecycle</string>",
		"<string>_warptweet</string>",
		"<key>KeepAlive</key><false/>",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("plist omits %q", required)
		}
	}
	if strings.Contains(text, "--once") {
		t.Fatal("default managed plist unexpectedly disables bounded in-process restart")
	}
	once, _, err := renderTunnelPlist("db-1", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(once), "<string>--once</string>") != 1 {
		t.Fatal("once plist does not contain exactly one --once argument")
	}
	if _, _, err := renderTunnelPlist(`db</string>`, false, true); err == nil {
		t.Fatal("plist renderer accepted XML injection")
	}
}

func TestParseTunnelJobBindsProgramAndPID(t *testing.T) {
	t.Parallel()

	label := "com.warptweet.tunnel.db-1"
	job, err := parseTunnelJob(label, "{\n\tprogram = /Library/Application Support/WarpTweet/bin/warptweet\n\tpid = 4321\n}\n")
	if err != nil || !job.loaded || job.pid != 4321 {
		t.Fatalf("parseTunnelJob = %+v, %v", job, err)
	}
	for _, output := range []string{
		"program = /tmp/warptweet\npid = 4321\n",
		"program = /Library/Application Support/WarpTweet/bin/warptweet\npid = nope\n",
		"program = /Library/Application Support/WarpTweet/bin/warptweet\npid = 1\npid = 2\n",
		"pid = 4321\n",
	} {
		if _, err := parseTunnelJob(label, output); err == nil {
			t.Fatalf("accepted unbound launchd output %q", output)
		}
	}
}
