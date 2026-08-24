package enrollment

import (
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/profile"
)

func TestValidatePublicKeyLineIgnoresBlobSubstrings(t *testing.T) {
	t.Parallel()
	selected, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatal(err)
	}
	blob := "AAAA" + strings.Repeat("A", 32) + "seedprivateAAAA"
	keyType := selected.AuthenticationKeyType

	tests := []struct {
		name    string
		line    string
		wantErr string
	}{
		{
			name: "blob may contain seed and private",
			line: keyType + " " + blob + " warptweet-client-example",
		},
		{
			name:    "comment must not contain private",
			line:    keyType + " " + blob + " comment-private-key",
			wantErr: "private-key material",
		},
		{
			name:    "comment must not contain seed",
			line:    keyType + " " + blob + " seed-comment",
			wantErr: "private-key material",
		},
		{
			name:    "comment must not contain begin openssh",
			line:    keyType + " " + blob + " begin openssh extra",
			wantErr: "private-key material",
		},
		{
			name:    "wrong key type is rejected before the blob scan",
			line:    "ssh-ed25519 " + blob + " comment",
			wantErr: "required composite algorithm",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validatePublicKeyLine(test.line)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error %v, want substring %q", err, test.wantErr)
			}
		})
	}
}
