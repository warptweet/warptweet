package engine

import (
	"strings"
	"testing"
)

func TestInspectServerAccountDataAcceptsPublicKeyOnlyTunnelAndLockedPrivsepAccounts(t *testing.T) {
	passwd, group, shadow := validServerAccountDatabases()
	evidence, err := inspectServerAccountData("warptweet", passwd, group, shadow)
	if err != nil {
		t.Fatalf("inspectServerAccountData: %v", err)
	}
	if evidence.dedicatedUID != 900 || evidence.dedicatedGID != 900 ||
		evidence.privsepUID != 901 || evidence.privsepGID != 901 {
		t.Fatalf("unexpected account evidence: %+v", evidence)
	}
}

func TestInspectServerAccountDataAcceptsPrivsepExclamationLockPrefix(t *testing.T) {
	passwd, group, shadow := validServerAccountDatabases()
	shadow = []byte(strings.Replace(
		string(shadow),
		"warptweet-sshd:!:",
		"warptweet-sshd:!$6$disabled:",
		1,
	))
	if _, err := inspectServerAccountData("warptweet", passwd, group, shadow); err != nil {
		t.Fatalf("inspectServerAccountData: %v", err)
	}
}

func TestInspectServerAccountDataRejectsUnsafeReuseAndAccountDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte, []byte, []byte) ([]byte, []byte, []byte)
		want   string
	}{
		{
			name: "dedicated root UID",
			mutate: replaceServerAccountDatabase(
				"warptweet:x:900:900:",
				"warptweet:x:0:900:",
				"passwd",
			),
			want: "UID and primary GID must both be nonzero",
		},
		{
			name: "dedicated reused UID",
			mutate: replaceServerAccountDatabase(
				"database:x:902:902:",
				"database:x:900:902:",
				"passwd",
			),
			want: "UID 900 is also used",
		},
		{
			name: "dedicated reused primary GID",
			mutate: replaceServerAccountDatabase(
				"database:x:902:902:",
				"database:x:902:900:",
				"passwd",
			),
			want: "primary GID 900 is also used",
		},
		{
			name: "dedicated wrong home",
			mutate: replaceServerAccountDatabase(
				":/nonexistent:/usr/sbin/nologin",
				":/home/warptweet:/usr/sbin/nologin",
				"passwd",
			),
			want: "home is",
		},
		{
			name: "dedicated login shell",
			mutate: replaceServerAccountDatabase(
				"warptweet:x:900:900::/nonexistent:/usr/sbin/nologin",
				"warptweet:x:900:900::/nonexistent:/bin/sh",
				"passwd",
			),
			want: "shell is",
		},
		{
			name: "dedicated wrong primary group",
			mutate: replaceServerAccountDatabase(
				"warptweet:x:900:",
				"warptweet:x:999:",
				"group",
			),
			want: "group \"warptweet\" has GID",
		},
		{
			name: "dedicated supplementary group",
			mutate: replaceServerAccountDatabase(
				"database:x:902:",
				"database:x:902:warptweet",
				"group",
			),
			want: "supplementary member",
		},
		{
			name: "dedicated group reused by member",
			mutate: replaceServerAccountDatabase(
				"warptweet:x:900:",
				"warptweet:x:900:database",
				"group",
			),
			want: "must not list supplementary members",
		},
		{
			name: "dedicated group password does not delegate",
			mutate: replaceServerAccountDatabase(
				"warptweet:x:900:",
				"warptweet:!:900:",
				"group",
			),
			want: "password field must delegate",
		},
		{
			name: "dedicated conventional Linux lock",
			mutate: replaceServerAccountDatabase(
				"warptweet:*NP*:",
				"warptweet:!:",
				"shadow",
			),
			want: "dedicated public-key-only sentinel",
		},
		{
			name: "dedicated generic impossible password",
			mutate: replaceServerAccountDatabase(
				"warptweet:*NP*:",
				"warptweet:*:",
				"shadow",
			),
			want: "dedicated public-key-only sentinel",
		},
		{
			name: "dedicated near miss sentinel",
			mutate: replaceServerAccountDatabase(
				"warptweet:*NP*:",
				"warptweet:*NP*!:",
				"shadow",
			),
			want: "dedicated public-key-only sentinel",
		},
		{
			name: "dedicated password hash",
			mutate: replaceServerAccountDatabase(
				"warptweet:*NP*:",
				"warptweet:$6$unsafe:",
				"shadow",
			),
			want: "dedicated public-key-only sentinel",
		},
		{
			name: "privsep wrong home",
			mutate: replaceServerAccountDatabase(
				"warptweet-sshd:x:901:901::/var/empty/warptweet-sshd:/usr/sbin/nologin",
				"warptweet-sshd:x:901:901::/nonexistent:/usr/sbin/nologin",
				"passwd",
			),
			want: "privilege-separation account: home is",
		},
		{
			name: "privsep public key sentinel",
			mutate: replaceServerAccountDatabase(
				"warptweet-sshd:!:",
				"warptweet-sshd:*NP*:",
				"shadow",
			),
			want: "shadow password must be genuinely locked",
		},
		{
			name: "privsep generic impossible password",
			mutate: replaceServerAccountDatabase(
				"warptweet-sshd:!:",
				"warptweet-sshd:*:",
				"shadow",
			),
			want: "shadow password must be genuinely locked",
		},
		{
			name: "privsep arbitrary star prefix",
			mutate: replaceServerAccountDatabase(
				"warptweet-sshd:!:",
				"warptweet-sshd:*disabled:",
				"shadow",
			),
			want: "shadow password must be genuinely locked",
		},
		{
			name: "privsep password hash",
			mutate: replaceServerAccountDatabase(
				"warptweet-sshd:!:",
				"warptweet-sshd:$6$unsafe:",
				"shadow",
			),
			want: "shadow password must be genuinely locked",
		},
		{
			name: "accounts share UID",
			mutate: replaceServerAccountDatabase(
				"warptweet-sshd:x:901:901:",
				"warptweet-sshd:x:900:901:",
				"passwd",
			),
			want: "UID 900 is also used",
		},
		{
			name: "malformed group database",
			mutate: func(passwd, group, shadow []byte) ([]byte, []byte, []byte) {
				return passwd, []byte("malformed\n"), shadow
			},
			want: "invalid field structure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			passwd, group, shadow := validServerAccountDatabases()
			passwd, group, shadow = test.mutate(passwd, group, shadow)
			_, err := inspectServerAccountData("warptweet", passwd, group, shadow)
			if err == nil {
				t.Fatal("inspectServerAccountData accepted an unsafe Unix account contract")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want substring %q", err, test.want)
			}
		})
	}
}

func TestInspectServerAccountDataDoesNotExposeShadowPasswordValues(t *testing.T) {
	tests := []struct {
		name              string
		existing          string
		untrustedPassword string
	}{
		{
			name:              "dedicated tunnel account",
			existing:          "warptweet:*NP*:",
			untrustedPassword: "$6$dedicated-must-not-appear-in-errors",
		},
		{
			name:              "privilege separation account",
			existing:          "warptweet-sshd:!:",
			untrustedPassword: "$6$privsep-must-not-appear-in-errors",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			passwd, group, shadow := validServerAccountDatabases()
			accountName, _, _ := strings.Cut(test.existing, ":")
			shadow = []byte(strings.Replace(
				string(shadow),
				test.existing,
				accountName+":"+test.untrustedPassword+":",
				1,
			))
			_, err := inspectServerAccountData("warptweet", passwd, group, shadow)
			if err == nil {
				t.Fatal("inspectServerAccountData accepted an unsafe password hash")
			}
			if strings.Contains(err.Error(), test.untrustedPassword) ||
				strings.Contains(err.Error(), "must-not-appear-in-errors") {
				t.Fatalf("validation error exposed a shadow password value: %q", err)
			}
		})
	}
}

func validServerAccountDatabases() ([]byte, []byte, []byte) {
	passwd := []byte(strings.Join([]string{
		"root:x:0:0:root:/root:/bin/sh",
		"warptweet:x:900:900::/nonexistent:/usr/sbin/nologin",
		"warptweet-sshd:x:901:901::/var/empty/warptweet-sshd:/usr/sbin/nologin",
		"database:x:902:902::/nonexistent:/usr/sbin/nologin",
	}, "\n") + "\n")
	group := []byte(strings.Join([]string{
		"root:x:0:",
		"warptweet:x:900:",
		"warptweet-sshd:x:901:",
		"database:x:902:",
	}, "\n") + "\n")
	shadow := []byte(strings.Join([]string{
		"root:*:1:0:99999:7:::",
		"warptweet:*NP*:1:0:99999:7:::",
		"warptweet-sshd:!:1:0:99999:7:::",
		"database:!:1:0:99999:7:::",
	}, "\n") + "\n")
	return passwd, group, shadow
}

func replaceServerAccountDatabase(old, replacement, database string) func(
	[]byte,
	[]byte,
	[]byte,
) ([]byte, []byte, []byte) {
	return func(passwd, group, shadow []byte) ([]byte, []byte, []byte) {
		switch database {
		case "passwd":
			passwd = []byte(strings.Replace(string(passwd), old, replacement, 1))
		case "group":
			group = []byte(strings.Replace(string(group), old, replacement, 1))
		case "shadow":
			shadow = []byte(strings.Replace(string(shadow), old, replacement, 1))
		default:
			panic("unknown account database")
		}
		return passwd, group, shadow
	}
}
