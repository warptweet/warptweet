// Package installlayout defines the fixed WarpTweet production filesystem
// contract. Security preflight does not accept caller-selected engine,
// client-state, or receipt paths.
package installlayout

const (
	ControllerPath              = "/opt/warptweet/bin/warptweet"
	ClientStateRoot             = "/etc/warptweet"
	ClientManifestPath          = ClientStateRoot + "/client.wt"
	ClientIdentityDirectory     = ClientStateRoot + "/identity"
	ClientIdentityPath          = ClientIdentityDirectory + "/client"
	ClientTrustDirectory        = "/etc/warptweet/trust"
	ClientKnownHostsPath        = ClientTrustDirectory + "/known_hosts"
	ClientGlobalKnownHostsPath  = ClientTrustDirectory + "/known_hosts.empty"
	ClientRuntimeRoot           = "/run/warptweet/tunnels"
	ClientServiceUser           = "warptweet-client"
	ClientServiceGroup          = "warptweet-client"
	OpenSSHPrefix               = "/opt/warptweet/libexec/openssh"
	SSHPath                     = OpenSSHPrefix + "/bin/ssh"
	SSHKeygenPath               = OpenSSHPrefix + "/bin/ssh-keygen"
	SSHDPath                    = OpenSSHPrefix + "/sbin/sshd"
	SSHDAuthPath                = OpenSSHPrefix + "/libexec/sshd-auth"
	SSHDSessionPath             = OpenSSHPrefix + "/libexec/sshd-session"
	ServerConfigPath            = "/etc/warptweet/sshd_config"
	ServerManifestPath          = "/etc/warptweet/server.wt"
	ServerHostKeyPath           = "/var/lib/warptweet/ssh/ssh_host_mldsa44_ed25519_key"
	ServerEnrollmentDirectory   = "/etc/warptweet/enrollment"
	ServerEnrollmentTLSCertPath = ServerEnrollmentDirectory + "/tls.crt"
	ServerEnrollmentTLSKeyPath  = ServerEnrollmentDirectory + "/tls.key"
	AuthorizedKeysDirectory     = "/var/lib/warptweet/authorized_keys"
	ClientsDirectory            = "/var/lib/warptweet/clients"
	HostAuthorizationPolicyPath = "/etc/warptweet/host-authorization.json"
	HostClockObservationPath    = "/var/lib/warptweet/clock-observation.json"
	GrantSessionsDirectory      = "/var/lib/warptweet/sessions"
	GrantSessionSocket          = "/run/warptweet/server/grant-session.sock"
	GrantAuthorityLockPath      = "/var/lib/warptweet/sessions/grant.lock"
	DataPlaneBootIDPath         = "/var/lib/warptweet/sessions/boot.id"
	DataPlaneControlSocket      = "/run/warptweet/sshd/control.sock"
	HostSignSocket              = "/run/warptweet/hostsign/sign.sock"
	HostClockBlockedPath        = "/var/lib/warptweet/blocked-clock.json"
	ClientRoutesDirectory       = "/etc/warptweet/routes"
	LinuxProvisionerPath        = "/opt/warptweet/bin/warptweet-provisioner"
	LinuxProvisionerRunRoot     = "/run/warptweet"
	LinuxProvisionerSocket      = LinuxProvisionerRunRoot + "/provisioner.sock"
	LinuxOperatorGroup          = "warptweet-operator"
	LinuxHostUID                = 900
	LinuxHostGID                = 900
	LinuxPrivsepUID             = 901
	LinuxPrivsepGID             = 901
	LinuxClientUID              = 920
	LinuxClientGID              = 920
	LinuxOperatorGID            = 923
	OpenSSHSourceReceiptPath    = "/opt/warptweet/share/openssh-source.txt"
	OpenSSLSourceReceiptPath    = "/opt/warptweet/share/openssl-source.txt"
	OpenSSHLicensePath          = "/opt/warptweet/share/licenses/openssh/LICENCE"
	OpenSSLLicensePath          = "/opt/warptweet/share/licenses/openssl/LICENSE.txt"
	OpenSSHBundleManifestPath   = "/opt/warptweet/share/openssh-bundle.sha256"
	PrivsepUser                 = "warptweet-sshd"
	PrivsepDirectory            = "/var/empty/warptweet-sshd"
)
