package profile

import "testing"

func TestCurrentProfileBindsStaticOpenSSLRuntime(t *testing.T) {
	t.Parallel()

	selected, err := Lookup(CurrentID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if selected.ID != "warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20" ||
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

func TestLookupRejectsPreChaCha20ProfileID(t *testing.T) {
	t.Parallel()

	if _, err := Lookup("warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519"); err == nil {
		t.Fatal("Lookup accepted the retired two-cipher profile ID")
	}
}

func TestCurrentProfilePinsOnlyChaCha20(t *testing.T) {
	t.Parallel()

	selected, err := Lookup(CurrentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Ciphers) != 1 || selected.Ciphers[0] != "chacha20-poly1305@openssh.com" {
		t.Fatalf("ciphers=%q", selected.Ciphers)
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
