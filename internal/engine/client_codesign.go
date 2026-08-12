package engine

// productionCodeSigningTeamID is the exact Apple Team ID required for
// production Darwin client executables. It remains empty until release
// identity publication configures it. An empty value fails closed.
const productionCodeSigningTeamID = ""

func verifyProductionClientCodeSignature(path string) error {
	return verifyProductionClientCodeSignaturePlatform(path)
}
