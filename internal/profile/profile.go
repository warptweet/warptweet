// Package profile defines immutable cryptographic profiles understood by WarpTweet.
package profile

import (
	"fmt"

	"warptweet.com/warptweet/internal/opensshsource"
)

const (
	CurrentID = "warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20"

	OpenSSLVersion     = "3.5.7"
	OpenSSLVersionText = "OpenSSL 3.5.7 9 Jun 2026"
	OpenSSLLinkage     = "static"
	ExecutableFormat   = "ELF"

	// AuthenticationBindingOpenSSHVendor is OpenSSH's vendor-qualified composite
	// authentication binding. It is not an IETF-standardized SSH authentication name.
	AuthenticationBindingOpenSSHVendor AuthenticationBindingStatus = "openssh-vendor-qualified"

	// SupportStatusPublishedMatrix means support is limited to the published
	// platform and evidence matrix for the release.
	SupportStatusPublishedMatrix SupportStatus = "published-matrix"
)

// AuthenticationBindingStatus is the standards posture of the SSH authentication
// key type selected by a profile.
type AuthenticationBindingStatus string

// SupportStatus is the product support posture for a profile on the published
// platform and evidence matrix.
type SupportStatus string

// Profile binds a product-level identifier to exact SSH wire algorithms.
// Changing any wire name or security rule requires a new profile ID.
type Profile struct {
	ID                          string
	EngineVersion               string
	OpenSSLVersion              string
	OpenSSLVersionText          string
	OpenSSLLinkage              string
	ExecutableFormat            string
	KeyExchangeAlgorithm        string
	AuthenticationKeyType       string
	RawPublicKeyBytes           int
	RawSignatureBytes           int
	Ciphers                     []string
	AuthenticationBindingStatus AuthenticationBindingStatus
	SupportStatus               SupportStatus
}

var current = Profile{
	ID:                    CurrentID,
	EngineVersion:         opensshsource.EngineVersion,
	OpenSSLVersion:        OpenSSLVersion,
	OpenSSLVersionText:    OpenSSLVersionText,
	OpenSSLLinkage:        OpenSSLLinkage,
	ExecutableFormat:      ExecutableFormat,
	KeyExchangeAlgorithm:  "mlkem768x25519-sha256",
	AuthenticationKeyType: "ssh-mldsa44-ed25519@openssh.com",
	RawPublicKeyBytes:     1344,
	RawSignatureBytes:     2484,
	Ciphers: []string{
		"chacha20-poly1305@openssh.com",
	},
	AuthenticationBindingStatus: AuthenticationBindingOpenSSHVendor,
	SupportStatus:               SupportStatusPublishedMatrix,
}

// Lookup returns a defensive copy of a supported immutable profile.
func Lookup(id string) (Profile, error) {
	if id != CurrentID {
		return Profile{}, fmt.Errorf("unsupported cryptographic profile %q", id)
	}

	result := current
	result.Ciphers = append([]string(nil), current.Ciphers...)
	return result, nil
}
