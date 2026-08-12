// Package installlayout defines the fixed WarpTweet production filesystem
// contract. Security preflight does not accept caller-selected engine,
// client-state, or receipt paths.
package installlayout

const (
	ControllerPath             = "/opt/warptweet/bin/warptweet"
	ClientManifestPath         = "/etc/warptweet/client.wt"
	ClientIdentityDirectory    = "/etc/warptweet/identity"
	ClientIdentityPath         = ClientIdentityDirectory + "/client"
	ClientTrustDirectory       = "/etc/warptweet/trust"
	ClientKnownHostsPath       = ClientTrustDirectory + "/known_hosts"
	ClientGlobalKnownHostsPath = ClientTrustDirectory + "/known_hosts.empty"
	ClientRuntimeRoot          = "/run/warptweet/tunnels"
	ClientServiceUser          = "warptweet-client"
	ClientServiceGroup         = "warptweet-client"
	OpenSSHPrefix              = "/opt/warptweet/libexec/openssh"
	SSHPath                    = OpenSSHPrefix + "/bin/ssh"
	SSHKeygenPath              = OpenSSHPrefix + "/bin/ssh-keygen"
	SSHDPath                   = OpenSSHPrefix + "/sbin/sshd"
	SSHDAuthPath               = OpenSSHPrefix + "/libexec/sshd-auth"
	SSHDSessionPath            = OpenSSHPrefix + "/libexec/sshd-session"
	ServerConfigPath           = "/opt/warptweet/etc/sshd_config"
	ServerManifestPath         = "/etc/warptweet/server.wt"
	ServerHostKeyPath          = "/opt/warptweet/etc/ssh_host_mldsa44_ed25519_key"
	AuthorizedKeysDirectory    = "/opt/warptweet/etc/authorized_keys"
	OpenSSHSourceReceiptPath   = "/opt/warptweet/share/openssh-source.txt"
	OpenSSLSourceReceiptPath   = "/opt/warptweet/share/openssl-source.txt"
	OpenSSHLicensePath         = "/opt/warptweet/share/licenses/openssh/LICENCE"
	OpenSSLLicensePath         = "/opt/warptweet/share/licenses/openssl/LICENSE.txt"
	OpenSSHBundleManifestPath  = "/opt/warptweet/share/openssh-bundle.sha256"
	PrivsepUser                = "warptweet-sshd"
	PrivsepDirectory           = "/var/empty/warptweet-sshd"
)
