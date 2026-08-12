//go:build !darwin

package engine

func verifyProductionClientCodeSignaturePlatform(string) error {
	return nil
}
