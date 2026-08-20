package command

import (
	"errors"
	"testing"

	"warptweet.com/warptweet/internal/routestate"
)

type reservedJournalStore struct {
	writes   []routestate.Transaction
	writeErr error
	calls    int
}

func (store *reservedJournalStore) ReserveAndWriteTransaction(transaction routestate.Transaction) error {
	store.calls++
	store.writes = append(store.writes, transaction)
	return store.writeErr
}

func (store *reservedJournalStore) LoadTransaction(string) (routestate.Transaction, error) {
	return routestate.Transaction{}, errors.New("unused")
}

func (store *reservedJournalStore) WriteTransaction(routestate.Transaction) error {
	return errors.New("unused")
}

func TestPersistReservedRouteUsesOneStoreOperation(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("reserved journal write failed")
	store := &reservedJournalStore{writeErr: writeErr}
	err := persistReservedRoute(store, "studio-mac", 15432, "invite-1", "gen-1")
	if !errors.Is(err, writeErr) {
		t.Fatalf("err=%v", err)
	}
	if store.calls != 1 {
		t.Fatalf("calls=%d", store.calls)
	}
	got := store.writes[0]
	if got.Phase != routestate.PhaseReserved || got.ListenPort != 15432 || got.InviteID != "invite-1" || got.Generation != "gen-1" {
		t.Fatalf("write=%+v", got)
	}
}

func TestPersistEnrolledRouteReturnsWriteError(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("enrolled journal write failed")
	store := &journalStore{writeErr: writeErr}
	err := persistEnrolledRoute(store, "studio-mac", 15432, "invite-1", "gen-1")
	if !errors.Is(err, writeErr) {
		t.Fatalf("err=%v", err)
	}
	if len(store.writes) != 1 || store.writes[0].Phase != routestate.PhaseEnrolled {
		t.Fatalf("writes=%+v", store.writes)
	}
}
