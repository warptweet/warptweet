package grant

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledDefaultDurations(t *testing.T) {
	t.Parallel()

	policy := InstalledDefault()
	if err := Validate(policy); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if policy.DefaultAuthorizationDurationSeconds != 2592000 {
		t.Fatalf("default=%d, want 2592000", policy.DefaultAuthorizationDurationSeconds)
	}
	if policy.MaximumAuthorizationDurationSeconds != 31536000 {
		t.Fatalf("maximum=%d, want 31536000", policy.MaximumAuthorizationDurationSeconds)
	}
}

func TestResolveDurationRejectsAboveMaximum(t *testing.T) {
	t.Parallel()

	policy := InstalledDefault()
	got, err := ResolveDuration(policy, 0)
	if err != nil || got != 2592000 {
		t.Fatalf("default resolve=%d %v", got, err)
	}
	got, err = ResolveDuration(policy, 3600)
	if err != nil || got != 3600 {
		t.Fatalf("shorter resolve=%d %v", got, err)
	}
	got, err = ResolveDuration(policy, 31536000)
	if err != nil || got != 31536000 {
		t.Fatalf("maximum resolve=%d %v", got, err)
	}
	if _, err := ResolveDuration(policy, 31536001); err == nil || !strings.Contains(err.Error(), "exceeds host maximum") {
		t.Fatalf("above maximum err=%v", err)
	}
}

func TestLoadPolicyMissingUsesDefault(t *testing.T) {
	t.Parallel()

	policy, err := LoadPolicy(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if policy.DefaultAuthorizationDurationSeconds != InstalledDefault().DefaultAuthorizationDurationSeconds {
		t.Fatalf("policy=%+v", policy)
	}
}

func TestLoadPolicyRejectsUnknownAndUnordered(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"kind":"warptweet.host-authorization-policy","schema_version":1,"default_authorization_duration_seconds":100,"maximum_authorization_duration_seconds":50}`+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted maximum below default")
	}
	if err := os.WriteFile(path, []byte(`{"kind":"warptweet.host-authorization-policy","schema_version":1,"default_authorization_duration_seconds":30,"maximum_authorization_duration_seconds":60,"extra":true}`+"\n"), 0o644); err != nil {
		t.Fatalf("write unknown: %v", err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted unknown field")
	}
	if err := os.WriteFile(path, []byte(`{"kind":"warptweet.host-authorization-policy","schema_version":1,"default_authorization_duration_seconds":30,"default_authorization_duration_seconds":30,"maximum_authorization_duration_seconds":60}`+"\n"), 0o644); err != nil {
		t.Fatalf("write duplicate: %v", err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted duplicate object name")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, maxPolicyBytes+1), 0o644); err != nil {
		t.Fatalf("write oversized: %v", err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted oversized policy")
	}
}

func TestWritePolicyRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.json")
	want := InstalledDefault()
	want.DefaultAuthorizationDurationSeconds = 3600
	want.MaximumAuthorizationDurationSeconds = 7200
	if err := WritePolicy(path, want); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if got != want {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}
