package installlayout

// Darwin package-owned client layout. Paths are installation invariants and are
// never selected by a .wt manifest. The runtime root is intentionally short so
// the control-socket path stays within the Unix-domain sun_path budget used by
// authenticated-forward readiness.
const (
	DarwinApplicationSupportRoot     = "/Library/Application Support/WarpTweet"
	DarwinControllerPath             = DarwinApplicationSupportRoot + "/bin/warptweet"
	DarwinClientStateRoot            = DarwinApplicationSupportRoot + "/state"
	DarwinClientManifestPath         = DarwinClientStateRoot + "/client.wt"
	DarwinClientIdentityDirectory    = DarwinClientStateRoot + "/identity"
	DarwinClientIdentityPath         = DarwinClientIdentityDirectory + "/client"
	DarwinClientTrustDirectory       = DarwinClientStateRoot + "/trust"
	DarwinClientKnownHostsPath       = DarwinClientTrustDirectory + "/known_hosts"
	DarwinClientGlobalKnownHostsPath = DarwinClientTrustDirectory + "/known_hosts.empty"
	DarwinClientRoutesDirectory      = DarwinClientStateRoot + "/routes"
	DarwinOpenSSHPrefix              = DarwinApplicationSupportRoot + "/libexec/openssh"
	DarwinSSHPath                    = DarwinOpenSSHPrefix + "/bin/ssh"
	DarwinSSHKeygenPath              = DarwinOpenSSHPrefix + "/bin/ssh-keygen"
	DarwinShareRoot                  = DarwinApplicationSupportRoot + "/share"
	DarwinOpenSSHSourceReceiptPath   = DarwinShareRoot + "/openssh-source.txt"
	DarwinOpenSSLSourceReceiptPath   = DarwinShareRoot + "/openssl-source.txt"
	DarwinOpenSSHLicensePath         = DarwinShareRoot + "/licenses/openssh/LICENCE"
	DarwinOpenSSLLicensePath         = DarwinShareRoot + "/licenses/openssl/LICENSE.txt"
	DarwinOpenSSHBundleManifestPath  = DarwinShareRoot + "/openssh-bundle.sha256"
	// DarwinClientRuntimeRoot is short on purpose. The reverse-DNS cache domain
	// is retained for product identity elsewhere; the readiness socket path must
	// remain within the fixed control-socket length budget.
	DarwinClientRuntimeRoot  = "/Library/Caches/wt"
	DarwinClientServiceUser  = "_warptweet"
	DarwinClientServiceGroup = "_warptweet"
	DarwinProvisionerPath    = DarwinApplicationSupportRoot + "/bin/warptweet-provisioner"
	DarwinProvisionerRunRoot = "/var/run/warptweet"
	DarwinProvisionerSocket  = DarwinProvisionerRunRoot + "/provisioner.sock"
	DarwinLaunchDaemonRoot   = "/Library/LaunchDaemons"
	DarwinProvisionerLabel   = "com.warptweet.provisioner"
	DarwinTunnelLabelPrefix  = "com.warptweet.tunnel."
)
