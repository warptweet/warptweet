package profile

import "testing"

func TestCurrentProfileBindsStaticOpenSSLRuntime(t *testing.T) {
	t.Parallel()

	selected, err := Lookup(CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if selected.ID != "warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519" ||
		selected.OpenSSLVersion != "3.5.7" ||
		selected.OpenSSLVersionText != "OpenSSL 3.5.7 9 Jun 2026" ||
		selected.OpenSSLLinkage != "static" || selected.ExecutableFormat != "ELF" {
		t.Fatalf("unexpected current runtime profile: %#v", selected)
	}
	if selected.AuthenticationBindingStatus != AuthenticationBindingOpenSSHVendor ||
		selected.SupportStatus != SupportStatusPublishedMatrix {
		t.Fatalf("unexpected current status fields: %#v", selected)
	}
}

func TestLookupRejectsUnknownProfile(t *testing.T) {
	t.Parallel()

	if _, err := Lookup("pq-preferred"); err == nil {
		t.Fatal("Lookup accepted a non-versioned profile")
	}
}

func TestLookupReturnsDefensiveCipherCopy(t *testing.T) {
	t.Parallel()

	first, err := Lookup(CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	first.Ciphers[0] = "modified"

	second, err := Lookup(CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if second.Ciphers[0] == "modified" {
		t.Fatal("Lookup exposed mutable profile state")
	}
}
