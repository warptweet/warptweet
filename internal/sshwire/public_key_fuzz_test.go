package sshwire

import "testing"

func FuzzValidatePublicKeyBlob(f *testing.F) {
	f.Add("AAAA", "ssh-mldsa44-ed25519@openssh.com", 1344)
	f.Fuzz(func(t *testing.T, encoded, algorithm string, rawKeyBytes int) {
		if rawKeyBytes < 0 || rawKeyBytes > 4096 {
			return
		}
		_ = ValidatePublicKeyBlob(encoded, algorithm, rawKeyBytes)
	})
}
