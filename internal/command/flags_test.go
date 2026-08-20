package command

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCommandsRejectDuplicateFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		arguments []string
		wantError string
	}{
		{
			name:      "validate config",
			arguments: []string{"validate", "--config", "one.wt", "--config", "two.wt"},
			wantError: "--config may be specified only once",
		},
		{
			name:      "render server config",
			arguments: []string{"render-server", "--config", "one.wt", "--config", "two.wt"},
			wantError: "--config may be specified only once",
		},
		{
			name: "render client tunnel",
			arguments: []string{
				"render-client", "--config", "client.wt",
				"--tunnel", "one", "--tunnel", "two",
			},
			wantError: "--tunnel may be specified only once",
		},
		{
			name: "doctor config",
			arguments: []string{
				"doctor", "--config", "one.wt", "--config", "two.wt", "--tunnel", "one",
			},
			wantError: "--config may be specified only once",
		},
		{
			name: "run removed runtime directory",
			arguments: []string{
				"run", "--config", "client.wt", "--tunnel", "one",
				"--runtime-dir", "/run/one",
			},
			wantError: "flag provided but not defined",
		},
		{
			name: "run once",
			arguments: []string{
				"run", "--config", "client.wt", "--tunnel", "one", "--once", "--once",
			},
			wantError: "--once may be specified only once",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), test.arguments, nil, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("code = %d, want 2; stderr = %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), test.wantError)
			}
		})
	}
}
