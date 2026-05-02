package tcpguard

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func newSQLStateStoreForTest(t *testing.T) *SQLStateStore {
	t.Helper()
	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sqlx.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLStateStore(db)
	if err != nil {
		t.Fatalf("NewSQLStateStore() error = %v", err)
	}
	return store
}

func TestSQLStateStoreCountersBansAndSessions(t *testing.T) {
	store := newSQLStateStoreForTest(t)
	count, _, err := store.IncrementGlobal("203.0.113.10")
	if err != nil || count != 1 {
		t.Fatalf("IncrementGlobal() = %d, %v; want 1, nil", count, err)
	}
	count, _, err = store.IncrementGlobal("203.0.113.10")
	if err != nil || count != 2 {
		t.Fatalf("IncrementGlobal() = %d, %v; want 2, nil", count, err)
	}
	counter, err := store.GetGlobal("203.0.113.10")
	if err != nil || counter == nil || counter.Count != 2 {
		t.Fatalf("GetGlobal() = %#v, %v; want count 2", counter, err)
	}

	if err := store.SetBan("203.0.113.10", &BanInfo{Until: time.Now().Add(time.Hour), Reason: "test", StatusCode: 403}); err != nil {
		t.Fatalf("SetBan() error = %v", err)
	}
	ban, err := store.GetBan("203.0.113.10")
	if err != nil || ban == nil || ban.Reason != "test" {
		t.Fatalf("GetBan() = %#v, %v", ban, err)
	}

	sessions := []*SessionInfo{{UA: "ua", IP: "203.0.113.10", Created: time.Now(), LastSeen: time.Now()}}
	if err := store.PutSessions("alice", sessions); err != nil {
		t.Fatalf("PutSessions() error = %v", err)
	}
	got, err := store.GetSessions("alice")
	if err != nil || len(got) != 1 || got[0].IP != "203.0.113.10" {
		t.Fatalf("GetSessions() = %#v, %v", got, err)
	}
}

func TestSQLStateStoreAdvancedState(t *testing.T) {
	store := newSQLStateStoreForTest(t)
	if err := store.SlidingIncrement("login:alice", time.Minute); err != nil {
		t.Fatalf("SlidingIncrement() error = %v", err)
	}
	count, err := store.SlidingCount("login:alice", time.Minute)
	if err != nil || count != 1 {
		t.Fatalf("SlidingCount() = %d, %v; want 1, nil", count, err)
	}

	if err := store.RevokeToken("token-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}
	revoked, err := store.IsTokenRevoked("token-1")
	if err != nil || !revoked {
		t.Fatalf("IsTokenRevoked() = %v, %v; want true, nil", revoked, err)
	}

	trust := &DeviceTrust{Fingerprint: "fp", UserID: "alice", Verified: true}
	if err := store.SetDeviceTrust("fp", trust); err != nil {
		t.Fatalf("SetDeviceTrust() error = %v", err)
	}
	gotTrust, err := store.GetDeviceTrust("fp")
	if err != nil || gotTrust == nil || !gotTrust.Verified {
		t.Fatalf("GetDeviceTrust() = %#v, %v", gotTrust, err)
	}

	session := &SessionState{SessionID: "sid", UserID: "alice", MFAVerified: true}
	if err := store.SetSessionState("sid", session); err != nil {
		t.Fatalf("SetSessionState() error = %v", err)
	}
	gotSession, err := store.GetSessionState("sid")
	if err != nil || gotSession == nil || gotSession.UserID != "alice" {
		t.Fatalf("GetSessionState() = %#v, %v", gotSession, err)
	}

	lock := &AccountLockState{AccountID: "alice", Locked: true, Reason: "failed_login"}
	if err := store.SetAccountLock("alice", lock); err != nil {
		t.Fatalf("SetAccountLock() error = %v", err)
	}
	gotLock, err := store.GetAccountLockState("alice")
	if err != nil || gotLock == nil || !gotLock.Locked {
		t.Fatalf("GetAccountLockState() = %#v, %v", gotLock, err)
	}
}
