package engine

// productionCodeSigningTeamID is the exact Apple Team ID required for
// production Darwin client executables (Developer ID Application).
const productionCodeSigningTeamID = "CP4268Q8UF"

func verifyProductionClientCodeSignature(path string) error {
	return verifyProductionClientCodeSignaturePlatform(path)
}
