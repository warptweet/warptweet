// Package opensshsource records the exact upstream source identity bound to
// the current WarpTweet engine profile and authenticated build receipt.
package opensshsource

const (
	Version               = "10.4p1"
	EngineVersion         = "OpenSSH_10.4p1"
	Archive               = "openssh-10.4p1.tar.gz"
	SourceURL             = "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.4p1.tar.gz"
	SignatureURL          = SourceURL + ".asc"
	ReleaseKeyURL         = "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc"
	SourceSHA256          = "ef6026dd2aea8d56059638d5d3262902c892ceba9f88395835e0d06d3fb63238"
	ReleaseKeyFingerprint = "7168B983815A5EEF59A4ADFD2A3F414E736060BA"
)
