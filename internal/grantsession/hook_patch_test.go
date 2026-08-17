package grantsession

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrantPatchUnregistersOnMonitorTerm(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "third_party", "openssh", "patches", "0001-warptweet-grant-register.patch")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patch: %v", err)
	}
	text := string(contents)
	if !strings.Contains(text, "mm_answer_term") {
		t.Fatal("grant patch omits mm_answer_term")
	}
	if !strings.Contains(text, "warptweet_grant_unregister();") {
		t.Fatal("grant patch omits warptweet_grant_unregister")
	}
	termIndex := strings.Index(text, "mm_answer_term")
	exitIndex := strings.Index(text[termIndex:], "exit(res);")
	unregisterIndex := strings.Index(text[termIndex:], "warptweet_grant_unregister();")
	if exitIndex < 0 || unregisterIndex < 0 || unregisterIndex > exitIndex {
		t.Fatal("mm_answer_term must call warptweet_grant_unregister immediately before exit(res)")
	}
}
