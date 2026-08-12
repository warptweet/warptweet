// Package opensslsource defines the authenticated static OpenSSL source input
// for the Linux production OpenSSH bundle and the macOS client engine build.
package opensslsource

const (
	Version                = "3.5.7"
	Archive                = "openssl-3.5.7.tar.gz"
	SourceURL              = "https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz"
	SignatureURL           = SourceURL + ".asc"
	ReleaseKeyURL          = "https://openssl-library.org/source/pubkeys.asc"
	SourceSHA256           = "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
	ReleaseKeyFingerprint  = "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF"
	LogicalPrefix          = "/opt/warptweet/libexec/openssl-static"
	LogicalConfigDirectory = "/opt/warptweet/etc/openssl-static"
)
