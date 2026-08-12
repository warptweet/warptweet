package engine

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/installlayout"
)

const (
	expectedDedicatedAccountHome  = "/nonexistent"
	expectedServerAccountShell    = "/usr/sbin/nologin"
	maxServerAccountDatabaseBytes = 4 << 20
	dedicatedPasswordSentinel     = "*NP*"
)

type serverAccountEvidence struct {
	dedicatedUID uint64
	dedicatedGID uint64
	privsepUID   uint64
	privsepGID   uint64
	passwdSHA256 [sha256.Size]byte
	groupSHA256  [sha256.Size]byte
	shadowSHA256 [sha256.Size]byte
}

type serverAccountInspector func(string) (serverAccountEvidence, error)

type unixPasswdRecord struct {
	name            string
	shadowDelegated bool
	uid             uint64
	gid             uint64
	home            string
	shell           string
}

type unixGroupRecord struct {
	name            string
	shadowDelegated bool
	gid             uint64
	members         []string
}

type unixShadowRecord struct {
	name          string
	passwordState unixShadowPasswordState
}

type unixShadowPasswordState uint8

const (
	unixShadowPasswordOther unixShadowPasswordState = iota
	unixShadowPasswordPublicKeyOnly
	unixShadowPasswordLocked
)

type shadowPasswordRequirement uint8

const (
	requirePublicKeyOnlyPassword shadowPasswordRequirement = iota
	requireLockedPassword
)

func inspectServerAccountData(
	dedicatedUser string,
	passwdData,
	groupData,
	shadowData []byte,
) (serverAccountEvidence, error) {
	passwdRecords, err := parseUnixPasswd(passwdData)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	groupRecords, err := parseUnixGroup(groupData)
	if err != nil {
		return serverAccountEvidence{}, err
	}
	shadowRecords, err := parseUnixShadow(shadowData)
	if err != nil {
		return serverAccountEvidence{}, err
	}

	dedicated, err := validateServiceAccount(
		dedicatedUser,
		dedicatedUser,
		expectedDedicatedAccountHome,
		passwdRecords,
		groupRecords,
		shadowRecords,
		requirePublicKeyOnlyPassword,
	)
	if err != nil {
		return serverAccountEvidence{}, fmt.Errorf("dedicated tunnel account: %w", err)
	}
	privsep, err := validateServiceAccount(
		installlayout.PrivsepUser,
		installlayout.PrivsepUser,
		installlayout.PrivsepDirectory,
		passwdRecords,
		groupRecords,
		shadowRecords,
		requireLockedPassword,
	)
	if err != nil {
		return serverAccountEvidence{}, fmt.Errorf("OpenSSH privilege-separation account: %w", err)
	}
	if dedicated.uid == privsep.uid || dedicated.gid == privsep.gid {
		return serverAccountEvidence{}, errors.New(
			"dedicated tunnel and privilege-separation accounts must not share a UID or GID",
		)
	}

	return serverAccountEvidence{
		dedicatedUID: dedicated.uid,
		dedicatedGID: dedicated.gid,
		privsepUID:   privsep.uid,
		privsepGID:   privsep.gid,
		passwdSHA256: sha256.Sum256(passwdData),
		groupSHA256:  sha256.Sum256(groupData),
		shadowSHA256: sha256.Sum256(shadowData),
	}, nil
}

func validateServiceAccount(
	accountName,
	groupName,
	expectedHome string,
	passwdRecords []unixPasswdRecord,
	groupRecords []unixGroupRecord,
	shadowRecords []unixShadowRecord,
	passwordRequirement shadowPasswordRequirement,
) (unixPasswdRecord, error) {
	var account unixPasswdRecord
	accountCount := 0
	for _, record := range passwdRecords {
		if record.name == accountName {
			account = record
			accountCount++
		}
	}
	if accountCount != 1 {
		return unixPasswdRecord{}, fmt.Errorf("passwd contains %d entries for %q, want exactly one", accountCount, accountName)
	}
	if account.uid == 0 || account.gid == 0 {
		return unixPasswdRecord{}, errors.New("UID and primary GID must both be nonzero")
	}
	if account.uid > math.MaxUint32 || account.gid > math.MaxUint32 {
		return unixPasswdRecord{}, errors.New("UID or primary GID exceeds the Linux account range")
	}
	if !account.shadowDelegated {
		return unixPasswdRecord{}, errors.New("passwd password field must delegate to shadow with x")
	}
	if account.home != expectedHome {
		return unixPasswdRecord{}, fmt.Errorf("home is %q, want %q", account.home, expectedHome)
	}
	if account.shell != expectedServerAccountShell {
		return unixPasswdRecord{}, fmt.Errorf("shell is %q, want %q", account.shell, expectedServerAccountShell)
	}
	for _, record := range passwdRecords {
		if record.name == accountName {
			continue
		}
		if record.uid == account.uid {
			return unixPasswdRecord{}, fmt.Errorf("UID %d is also used by account %q", account.uid, record.name)
		}
		if record.gid == account.gid {
			return unixPasswdRecord{}, fmt.Errorf("primary GID %d is also used by account %q", account.gid, record.name)
		}
	}

	var primaryGroup unixGroupRecord
	primaryGroupCount := 0
	for _, group := range groupRecords {
		if group.name == groupName {
			primaryGroup = group
			primaryGroupCount++
		}
		for _, member := range group.members {
			if member == accountName {
				return unixPasswdRecord{}, fmt.Errorf("account is listed as a supplementary member of group %q", group.name)
			}
		}
	}
	if primaryGroupCount != 1 {
		return unixPasswdRecord{}, fmt.Errorf("group contains %d entries for %q, want exactly one", primaryGroupCount, groupName)
	}
	if primaryGroup.gid != account.gid {
		return unixPasswdRecord{}, fmt.Errorf(
			"primary GID is %d but group %q has GID %d",
			account.gid,
			groupName,
			primaryGroup.gid,
		)
	}
	if !primaryGroup.shadowDelegated {
		return unixPasswdRecord{}, fmt.Errorf("primary group %q password field must delegate with x", groupName)
	}
	if len(primaryGroup.members) != 0 {
		return unixPasswdRecord{}, fmt.Errorf("primary group %q must not list supplementary members", groupName)
	}
	for _, group := range groupRecords {
		if group.name != groupName && group.gid == account.gid {
			return unixPasswdRecord{}, fmt.Errorf("primary GID %d is also used by group %q", account.gid, group.name)
		}
	}

	shadowCount := 0
	shadowPasswordState := unixShadowPasswordOther
	for _, record := range shadowRecords {
		if record.name == accountName {
			shadowCount++
			shadowPasswordState = record.passwordState
		}
	}
	if shadowCount != 1 {
		return unixPasswdRecord{}, fmt.Errorf("shadow contains %d entries for %q, want exactly one", shadowCount, accountName)
	}
	switch passwordRequirement {
	case requirePublicKeyOnlyPassword:
		if shadowPasswordState != unixShadowPasswordPublicKeyOnly {
			return unixPasswdRecord{}, errors.New(
				"shadow password must use the dedicated public-key-only sentinel",
			)
		}
	case requireLockedPassword:
		if shadowPasswordState != unixShadowPasswordLocked {
			return unixPasswdRecord{}, errors.New("shadow password must be genuinely locked")
		}
	default:
		return unixPasswdRecord{}, errors.New("shadow password requirement is invalid")
	}
	return account, nil
}

func parseUnixPasswd(data []byte) ([]unixPasswdRecord, error) {
	lines, err := parseUnixAccountLines("passwd", data, 7)
	if err != nil {
		return nil, err
	}
	records := make([]unixPasswdRecord, 0, len(lines))
	for index, fields := range lines {
		uid, err := parseUnixID("passwd", index+1, "UID", string(fields[2]))
		if err != nil {
			return nil, err
		}
		gid, err := parseUnixID("passwd", index+1, "GID", string(fields[3]))
		if err != nil {
			return nil, err
		}
		records = append(records, unixPasswdRecord{
			name:            string(fields[0]),
			shadowDelegated: bytes.Equal(fields[1], []byte{'x'}),
			uid:             uid,
			gid:             gid,
			home:            string(fields[5]),
			shell:           string(fields[6]),
		})
	}
	return records, nil
}

func parseUnixGroup(data []byte) ([]unixGroupRecord, error) {
	lines, err := parseUnixAccountLines("group", data, 4)
	if err != nil {
		return nil, err
	}
	records := make([]unixGroupRecord, 0, len(lines))
	for index, fields := range lines {
		gid, err := parseUnixID("group", index+1, "GID", string(fields[2]))
		if err != nil {
			return nil, err
		}
		var members []string
		if len(fields[3]) != 0 {
			rawMembers := bytes.Split(fields[3], []byte{','})
			members = make([]string, 0, len(rawMembers))
			for _, member := range rawMembers {
				if len(member) == 0 {
					return nil, fmt.Errorf("group line %d contains an empty member", index+1)
				}
				members = append(members, string(member))
			}
		}
		records = append(records, unixGroupRecord{
			name:            string(fields[0]),
			shadowDelegated: bytes.Equal(fields[1], []byte{'x'}),
			gid:             gid,
			members:         members,
		})
	}
	return records, nil
}

func parseUnixShadow(data []byte) ([]unixShadowRecord, error) {
	lines, err := parseUnixAccountLines("shadow", data, 9)
	if err != nil {
		return nil, err
	}
	records := make([]unixShadowRecord, 0, len(lines))
	for _, fields := range lines {
		passwordState := unixShadowPasswordOther
		switch {
		case bytes.Equal(fields[1], []byte(dedicatedPasswordSentinel)):
			passwordState = unixShadowPasswordPublicKeyOnly
		case len(fields[1]) > 0 && fields[1][0] == '!':
			passwordState = unixShadowPasswordLocked
		}
		records = append(records, unixShadowRecord{
			name:          string(fields[0]),
			passwordState: passwordState,
		})
	}
	return records, nil
}

// parseUnixAccountLines returns byte slices backed by data. In particular it
// never converts an entire shadow database to an immutable Go string, so the
// caller can clear the bounded source buffer after classifying password state.
func parseUnixAccountLines(name string, data []byte, fieldCount int) ([][][]byte, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || !utf8.Valid(data) {
		return nil, fmt.Errorf("%s database must be non-empty, valid UTF-8, and LF-terminated", name)
	}
	if bytes.IndexByte(data, '\r') >= 0 || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("%s database contains a forbidden control byte", name)
	}
	rawLines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	lines := make([][][]byte, 0, len(rawLines))
	for index, line := range rawLines {
		if len(line) == 0 {
			return nil, fmt.Errorf("%s database line %d is empty", name, index+1)
		}
		fields := bytes.Split(line, []byte{':'})
		if len(fields) != fieldCount || len(fields[0]) == 0 {
			return nil, fmt.Errorf("%s database line %d has invalid field structure", name, index+1)
		}
		lines = append(lines, fields)
	}
	return lines, nil
}

func parseUnixID(database string, line int, field, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s database line %d has invalid %s %q", database, line, field, value)
	}
	return parsed, nil
}
