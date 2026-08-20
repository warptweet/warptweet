package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/outcome"
	"warptweet.com/warptweet/internal/routestate"
)

const enrollConnectJSON = `{"tunnel_id":"studio-mac","listen_endpoint":"127.0.0.1:15432","service_endpoint":"127.0.0.1:5432"}`

type journalStore struct {
	tx       routestate.Transaction
	loadErr  error
	writeErr error
	writes   []routestate.Transaction
}

func (store *journalStore) LoadTransaction(string) (routestate.Transaction, error) {
	if store.loadErr != nil {
		return routestate.Transaction{}, store.loadErr
	}
	return store.tx, nil
}

func (store *journalStore) WriteTransaction(transaction routestate.Transaction) error {
	store.writes = append(store.writes, transaction)
	if store.writeErr != nil {
		return store.writeErr
	}
	store.tx = transaction
	return nil
}

func connectJournalDeps(store *journalStore, upErr, repairErr error, upCalled, repairCalled *bool) commandDependencies {
	return commandDependencies{
		openRouteStore: func() (routeStore, error) {
			return store, nil
		},
		enroll: func(_ context.Context, _ []string, stdout, _ io.Writer) error {
			_, err := io.WriteString(stdout, enrollConnectJSON)
			return err
		},
		up: func(_ context.Context, _ []string, _, _ io.Writer, _ commandDependencies) error {
			if upCalled != nil {
				*upCalled = true
			}
			return upErr
		},
		repair: func(_ context.Context, _ []string, _, _ io.Writer, _ commandDependencies) error {
			if repairCalled != nil {
				*repairCalled = true
			}
			return repairErr
		},
	}
}

func TestConnectMissingTransactionProceedsToUp(t *testing.T) {
	t.Parallel()

	store := &journalStore{loadErr: os.ErrNotExist}
	var upCalled bool
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, nil, nil, &upCalled, nil))
	if err != nil {
		t.Fatalf("runConnect: %v", err)
	}
	if !upCalled {
		t.Fatal("missing transaction did not call up")
	}
	if len(store.writes) != 1 || store.writes[0].Phase != routestate.PhaseConnected {
		t.Fatalf("writes=%+v", store.writes)
	}
	if !strings.Contains(stdout.String(), "connected\n") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestConnectCorruptTransactionDoesNotCallUp(t *testing.T) {
	t.Parallel()

	loadErr := errors.New("corrupt transaction")
	store := &journalStore{loadErr: loadErr}
	var upCalled bool
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, io.Discard, io.Discard, connectJournalDeps(store, nil, nil, &upCalled, nil))
	if !errors.Is(err, loadErr) {
		t.Fatalf("err=%v", err)
	}
	if upCalled {
		t.Fatal("corrupt transaction called up")
	}
	if len(store.writes) != 0 {
		t.Fatalf("writes=%+v", store.writes)
	}
}

func populatedConnectTransaction(phase string) routestate.Transaction {
	return routestate.Transaction{
		RouteID:    "studio-mac",
		Phase:      phase,
		ListenPort: 15432,
		InviteID:   "invite-1",
		Generation: "gen-1",
		Error:      "previous start failed",
	}
}

func assertPreservedConnectMetadata(t *testing.T, got routestate.Transaction, phase, journalError string) {
	t.Helper()
	if got.RouteID != "studio-mac" || got.Phase != phase || got.ListenPort != 15432 ||
		got.InviteID != "invite-1" || got.Generation != "gen-1" || got.Error != journalError {
		t.Fatalf("write=%+v phase=%s error=%q", got, phase, journalError)
	}
}

func TestConnectEnrolledNotReadyRepairsThenPersistsConnected(t *testing.T) {
	t.Parallel()

	store := &journalStore{tx: populatedConnectTransaction(routestate.PhaseEnrolledNotReady)}
	var upCalled, repairCalled bool
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, nil, nil, &upCalled, &repairCalled))
	if err != nil {
		t.Fatalf("runConnect: %v", err)
	}
	if upCalled || !repairCalled {
		t.Fatalf("up=%v repair=%v", upCalled, repairCalled)
	}
	if len(store.writes) != 1 {
		t.Fatalf("writes=%+v", store.writes)
	}
	assertPreservedConnectMetadata(t, store.writes[0], routestate.PhaseConnected, "")
	if !strings.Contains(stdout.String(), "connected\n") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestConnectRepairWriteFailureDoesNotReportConnected(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("journal write failed")
	store := &journalStore{
		tx:       routestate.Transaction{RouteID: "studio-mac", Phase: routestate.PhaseEnrolledNotReady},
		writeErr: writeErr,
	}
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, nil, nil, nil, nil))
	if !errors.Is(err, writeErr) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(stdout.String(), "connected") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestConnectUpFailurePersistsEnrolledNotReady(t *testing.T) {
	t.Parallel()

	store := &journalStore{tx: populatedConnectTransaction(routestate.PhaseEnrolled)}
	upErr := errors.New("tunnel start failed")
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, upErr, nil, nil, nil))
	var coded *outcome.Error
	if !errors.As(err, &coded) || coded.Code != outcome.CodeEnrolledNotReady {
		t.Fatalf("err=%v", err)
	}
	if len(store.writes) != 1 {
		t.Fatalf("writes=%+v", store.writes)
	}
	assertPreservedConnectMetadata(t, store.writes[0], routestate.PhaseEnrolledNotReady, upErr.Error())
	if !strings.Contains(stdout.String(), "enrolled_not_ready\n") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestConnectSuccessfulStartPreservesLoadedMetadata(t *testing.T) {
	t.Parallel()

	store := &journalStore{tx: populatedConnectTransaction(routestate.PhaseEnrolled)}
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("runConnect: %v", err)
	}
	if len(store.writes) != 1 {
		t.Fatalf("writes=%+v", store.writes)
	}
	assertPreservedConnectMetadata(t, store.writes[0], routestate.PhaseConnected, "")
}

func TestConnectUpFailureWriteFailureDoesNotReportEnrolledNotReady(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("journal write failed")
	store := &journalStore{loadErr: os.ErrNotExist, writeErr: writeErr}
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, errors.New("tunnel start failed"), nil, nil, nil))
	if !errors.Is(err, writeErr) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(stdout.String(), "enrolled_not_ready") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestConnectConnectedWriteFailureDoesNotReportConnected(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("journal write failed")
	store := &journalStore{loadErr: os.ErrNotExist, writeErr: writeErr}
	var stdout bytes.Buffer
	err := runConnect(context.Background(), []string{"invite.wtinvite"}, &stdout, io.Discard, connectJournalDeps(store, nil, nil, nil, nil))
	if !errors.Is(err, writeErr) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(stdout.String(), "connected") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}
