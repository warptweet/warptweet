package enrollment

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeInviteLabel(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":                      "host",
		"  ":                    "host",
		"Studio Mac":            "studio-mac",
		"Curtis-MacBook":        "curtis-macbook",
		"DB_1.local":            "db-1-local",
		"---":                   "host",
		"123db":                 "n123db",
		strings.Repeat("a", 60): strings.Repeat("a", 48),
	}
	for input, want := range cases {
		if got := SanitizeInviteLabel(input); got != want {
			t.Fatalf("SanitizeInviteLabel(%q)=%q want %q", input, got, want)
		}
	}
}

func TestWriteInviteFileExclusiveAndCollisionSuffix(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inviteID := "a81f9c2d00112233445566778899aabb"
	first, err := WriteInviteFile(dir, "studio-mac", inviteID, []byte(`{"kind":"warptweet.invite"}`+"\n"))
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if filepath.Base(first) != "studio-mac.wtinvite" {
		t.Fatalf("first basename=%s", filepath.Base(first))
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode().Perm())
	}

	second, err := WriteInviteFile(dir, "studio-mac", inviteID, []byte(`{"kind":"warptweet.invite","n":2}`+"\n"))
	if err != nil {
		t.Fatalf("collision write: %v", err)
	}
	if filepath.Base(second) != "studio-mac-a81f.wtinvite" {
		t.Fatalf("second basename=%s", filepath.Base(second))
	}

	// Primary and 4-char suffix are already occupied by the first two writes.
	thirdPath := "studio-mac-a81f9c.wtinvite"
	third, err := WriteInviteFile(dir, "studio-mac", inviteID, []byte(`{"kind":"warptweet.invite","n":3}`+"\n"))
	if err != nil {
		t.Fatalf("six-char collision write: %v", err)
	}
	if filepath.Base(third) != thirdPath {
		t.Fatalf("third basename=%s want=%s", filepath.Base(third), thirdPath)
	}
}

func TestWriteInviteFileExactRefusesOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "alice.wtinvite")
	if _, err := WriteInviteFileExact(path, []byte("one\n")); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := WriteInviteFileExact(path, []byte("two\n")); !errors.Is(err, ErrInvitePathCollision) {
		t.Fatalf("second err=%v", err)
	}
}

func TestInviteCollisionFileName(t *testing.T) {
	t.Parallel()

	name, err := InviteCollisionFileName("Studio Mac", "AbCdEf12", 4)
	if err != nil {
		t.Fatalf("InviteCollisionFileName: %v", err)
	}
	if name != "studio-mac-abcd.wtinvite" {
		t.Fatalf("name=%s", name)
	}
}
