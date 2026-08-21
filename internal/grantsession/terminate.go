package grantsession

import (
	"fmt"
	"syscall"
	"time"
)

// TerminateSignals every matching session using pidfd-validated identity.
func (authority *Authority) Terminate(clientID, generation, publicKeySHA256 string) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.lock(); err != nil {
		return err
	}
	defer authority.unlock()
	records, err := authority.listMatching(matchGrantSessions(clientID, generation, publicKeySHA256))
	if err != nil {
		return err
	}
	var first error
	for _, record := range records {
		if isDataPlaneExe(record.Exe) {
			if err := dropDataPlaneSessions(record.KeyBlobSHA256); err != nil {
				if first == nil {
					first = err
				}
				continue
			}
			if err := osRemove(recordFile(authority.Root, record)); err != nil && first == nil {
				first = err
			}
			continue
		}
		identity := ProcessIdentity{BootID: record.BootID, PID: record.PID, StartTime: record.StartTime, Exe: record.Exe}
		if err := signalIdentity(identity, syscall.SIGTERM); err != nil && first == nil {
			first = err
		}
		if !waitIdentityGone(identity, 2*time.Second) {
			if err := signalIdentity(identity, syscall.SIGKILL); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// VerifyGone proves matching processes are gone, then clears records.
func (authority *Authority) VerifyGone(clientID, generation, publicKeySHA256 string) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.lock(); err != nil {
		return err
	}
	defer authority.unlock()
	records, err := authority.listMatching(matchGrantSessions(clientID, generation, publicKeySHA256))
	if err != nil {
		return err
	}
	for _, record := range records {
		if isDataPlaneExe(record.Exe) {
			return fmt.Errorf("data-plane session %s for client %s is still registered", record.ConnectionID, clientID)
		}
		identity := ProcessIdentity{BootID: record.BootID, PID: record.PID, StartTime: record.StartTime, Exe: record.Exe}
		if identityAlive(identity) {
			return fmt.Errorf("session pid %d for client %s generation %s is still running", record.PID, clientID, generation)
		}
		if err := osRemove(recordFile(authority.Root, record)); err != nil {
			return err
		}
	}
	return nil
}

// TerminateAll closes every recorded WarpTweet data-plane session.
func (authority *Authority) TerminateAll() error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.lock(); err != nil {
		return err
	}
	defer authority.unlock()
	records, err := authority.listMatching(func(Record) bool { return true })
	if err != nil {
		return err
	}
	var first error
	for _, record := range records {
		if isDataPlaneExe(record.Exe) {
			if err := dropDataPlaneSessions(record.KeyBlobSHA256); err != nil {
				if first == nil {
					first = err
				}
				continue
			}
			if err := osRemove(recordFile(authority.Root, record)); err != nil && first == nil {
				first = err
			}
			continue
		}
		identity := ProcessIdentity{BootID: record.BootID, PID: record.PID, StartTime: record.StartTime, Exe: record.Exe}
		if err := signalIdentity(identity, syscall.SIGTERM); err != nil && first == nil {
			first = err
		}
		if !waitIdentityGone(identity, 2*time.Second) {
			if err := signalIdentity(identity, syscall.SIGKILL); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func matchGrantSessions(clientID, generation, publicKeySHA256 string) func(Record) bool {
	return func(record Record) bool {
		if record.ClientID != clientID {
			return false
		}
		if generation != "" && record.Generation != generation {
			return false
		}
		if publicKeySHA256 != "" && record.PublicKeySHA256 != publicKeySHA256 {
			return false
		}
		return true
	}
}

func osRemove(path string) error {
	return removeIfPresent(path)
}
