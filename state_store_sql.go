package tcpguard

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
)

// SQLStateStore is a durable StateStore backed by SQL tables. It is suitable
// for production deployments that need shared counters, bans, sessions, token
// revocation, device trust, and account locks across application instances.
type SQLStateStore struct {
	db *sqlx.DB
	mu sync.Mutex
}

func NewSQLStateStore(db *sqlx.DB) (*SQLStateStore, error) {
	store := &SQLStateStore{db: db}
	if err := store.createTables(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *SQLStateStore) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tcpguard_counters (
		scope TEXT NOT NULL,
		key TEXT NOT NULL,
		count INTEGER NOT NULL,
		first_seen TIMESTAMP NOT NULL,
		last_reset TIMESTAMP NOT NULL,
		burst INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (scope, key)
	);
	CREATE TABLE IF NOT EXISTS tcpguard_bans (
		ip TEXT PRIMARY KEY,
		until_ts TIMESTAMP NOT NULL,
		permanent INTEGER NOT NULL,
		reason TEXT NOT NULL,
		status_code INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS tcpguard_user_sessions (
		user_id TEXT PRIMARY KEY,
		data TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS tcpguard_sliding_windows (
		key TEXT NOT NULL,
		ts TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_tcpguard_sliding_windows_key_ts ON tcpguard_sliding_windows(key, ts);
	CREATE TABLE IF NOT EXISTS tcpguard_revoked_tokens (
		token TEXT PRIMARY KEY,
		expiry TIMESTAMP NOT NULL
	);
	CREATE TABLE IF NOT EXISTS tcpguard_device_trust (
		fingerprint TEXT PRIMARY KEY,
		data TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS tcpguard_session_states (
		session_id TEXT PRIMARY KEY,
		data TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS tcpguard_account_locks (
		account_id TEXT PRIMARY KEY,
		data TEXT NOT NULL
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLStateStore) IncrementGlobal(ip string) (int, time.Time, error) {
	counter, err := s.incrementCounter("global", ip, 0, time.Now())
	if err != nil {
		return 0, time.Time{}, err
	}
	return counter.Count, counter.LastReset, nil
}

func (s *SQLStateStore) GetGlobal(ip string) (*RequestCounter, error) {
	return s.getRequestCounter("global", ip)
}

func (s *SQLStateStore) ResetGlobal(ip string) error {
	return s.deleteCounter("global", ip)
}

func (s *SQLStateStore) IncrementEndpoint(ip, endpoint string) (*RequestCounter, error) {
	return s.incrementCounter("endpoint", ip+"|"+endpoint, 0, time.Now())
}

func (s *SQLStateStore) GetEndpoint(ip, endpoint string) (*RequestCounter, error) {
	return s.getRequestCounter("endpoint", ip+"|"+endpoint)
}

func (s *SQLStateStore) IncrementActionCounter(key string, window time.Duration) (int, time.Time, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	counter, err := s.getGenericCounterLocked(key)
	if err != nil {
		return 0, time.Time{}, err
	}
	if counter == nil || now.Sub(counter.First) > window {
		counter = &GenericCounter{Count: 1, First: now}
	} else {
		counter.Count++
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO tcpguard_counters (scope, key, count, first_seen, last_reset, burst) VALUES (?, ?, ?, ?, ?, 0)`,
		"action", key, counter.Count, counter.First, counter.First)
	return counter.Count, counter.First, err
}

func (s *SQLStateStore) GetActionCounter(key string) (*GenericCounter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getGenericCounterLocked(key)
}

func (s *SQLStateStore) DeleteActionCounter(key string) error {
	return s.deleteCounter("action", key)
}

func (s *SQLStateStore) GetBan(ip string) (*BanInfo, error) {
	var ban BanInfo
	var permanent int
	err := s.db.QueryRow(`SELECT until_ts, permanent, reason, status_code FROM tcpguard_bans WHERE ip = ?`, ip).
		Scan(&ban.Until, &permanent, &ban.Reason, &ban.StatusCode)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ban.Permanent = permanent == 1
	if !ban.Permanent && time.Now().After(ban.Until) {
		_ = s.DeleteBan(ip)
		return nil, nil
	}
	return &ban, nil
}

func (s *SQLStateStore) SetBan(ip string, ban *BanInfo) error {
	permanent := 0
	if ban.Permanent {
		permanent = 1
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO tcpguard_bans (ip, until_ts, permanent, reason, status_code) VALUES (?, ?, ?, ?, ?)`,
		ip, ban.Until, permanent, ban.Reason, ban.StatusCode)
	return err
}

func (s *SQLStateStore) DeleteBan(ip string) error {
	_, err := s.db.Exec(`DELETE FROM tcpguard_bans WHERE ip = ?`, ip)
	return err
}

func (s *SQLStateStore) GetSessions(userID string) ([]*SessionInfo, error) {
	var raw string
	err := s.db.QueryRow(`SELECT data FROM tcpguard_user_sessions WHERE user_id = ?`, userID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sessions []*SessionInfo
	if err := json.Unmarshal([]byte(raw), &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *SQLStateStore) PutSessions(userID string, sessions []*SessionInfo) error {
	data, err := json.Marshal(sessions)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO tcpguard_user_sessions (user_id, data) VALUES (?, ?)`, userID, string(data))
	return err
}

func (s *SQLStateStore) SlidingIncrement(key string, window time.Duration) error {
	now := time.Now()
	cutoff := now.Add(-window)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM tcpguard_sliding_windows WHERE key = ? AND ts < ?`, key, cutoff); err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tcpguard_sliding_windows WHERE key = ?`, key).Scan(&count); err != nil {
		return err
	}
	if count >= maxSlidingWindowEntries {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO tcpguard_sliding_windows (key, ts) VALUES (?, ?)`, key, now)
	return err
}

func (s *SQLStateStore) SlidingCount(key string, window time.Duration) (int, error) {
	cutoff := time.Now().Add(-window)
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tcpguard_sliding_windows WHERE key = ? AND ts >= ?`, key, cutoff).Scan(&count)
	return count, err
}

func (s *SQLStateStore) RevokeToken(token string, expiry time.Time) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO tcpguard_revoked_tokens (token, expiry) VALUES (?, ?)`, token, expiry)
	return err
}

func (s *SQLStateStore) IsTokenRevoked(token string) (bool, error) {
	var expiry time.Time
	err := s.db.QueryRow(`SELECT expiry FROM tcpguard_revoked_tokens WHERE token = ?`, token).Scan(&expiry)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if time.Now().After(expiry) {
		_, _ = s.db.Exec(`DELETE FROM tcpguard_revoked_tokens WHERE token = ?`, token)
		return false, nil
	}
	return true, nil
}

func (s *SQLStateStore) GetDeviceTrust(fingerprint string) (*DeviceTrust, error) {
	var out DeviceTrust
	ok, err := s.getJSON("tcpguard_device_trust", "fingerprint", fingerprint, &out)
	if !ok || err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *SQLStateStore) SetDeviceTrust(fingerprint string, trust *DeviceTrust) error {
	return s.setJSON("tcpguard_device_trust", "fingerprint", fingerprint, trust)
}

func (s *SQLStateStore) GetSessionState(sessionID string) (*SessionState, error) {
	var out SessionState
	ok, err := s.getJSON("tcpguard_session_states", "session_id", sessionID, &out)
	if !ok || err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *SQLStateStore) SetSessionState(sessionID string, state *SessionState) error {
	return s.setJSON("tcpguard_session_states", "session_id", sessionID, state)
}

func (s *SQLStateStore) DeleteSessionState(sessionID string) error {
	_, err := s.db.Exec(`DELETE FROM tcpguard_session_states WHERE session_id = ?`, sessionID)
	return err
}

func (s *SQLStateStore) GetAccountLock(accountID string) (*AccountLockState, error) {
	var out AccountLockState
	ok, err := s.getJSON("tcpguard_account_locks", "account_id", accountID, &out)
	if !ok || err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *SQLStateStore) SetAccountLock(accountID string, lock *AccountLockState) error {
	return s.setJSON("tcpguard_account_locks", "account_id", accountID, lock)
}

func (s *SQLStateStore) DeleteAccountLock(accountID string) error {
	_, err := s.db.Exec(`DELETE FROM tcpguard_account_locks WHERE account_id = ?`, accountID)
	return err
}

func (s *SQLStateStore) GetAccountLockState(accountID string) (*AccountLockState, error) {
	return s.GetAccountLock(accountID)
}

func (s *SQLStateStore) HealthCheck() error {
	return s.db.Ping()
}

func (s *SQLStateStore) incrementCounter(scope, key string, burst int, now time.Time) (*RequestCounter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counter, err := s.getRequestCounterLocked(scope, key)
	if err != nil {
		return nil, err
	}
	if counter == nil {
		counter = &RequestCounter{Count: 1, LastReset: now, Burst: burst}
	} else {
		counter.Count++
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO tcpguard_counters (scope, key, count, first_seen, last_reset, burst) VALUES (?, ?, ?, ?, ?, ?)`,
		scope, key, counter.Count, now, counter.LastReset, counter.Burst)
	return counter, err
}

func (s *SQLStateStore) getRequestCounter(scope, key string) (*RequestCounter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getRequestCounterLocked(scope, key)
}

func (s *SQLStateStore) getRequestCounterLocked(scope, key string) (*RequestCounter, error) {
	var counter RequestCounter
	err := s.db.QueryRow(`SELECT count, last_reset, burst FROM tcpguard_counters WHERE scope = ? AND key = ?`, scope, key).
		Scan(&counter.Count, &counter.LastReset, &counter.Burst)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &counter, err
}

func (s *SQLStateStore) getGenericCounterLocked(key string) (*GenericCounter, error) {
	var counter GenericCounter
	err := s.db.QueryRow(`SELECT count, first_seen FROM tcpguard_counters WHERE scope = ? AND key = ?`, "action", key).
		Scan(&counter.Count, &counter.First)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &counter, err
}

func (s *SQLStateStore) deleteCounter(scope, key string) error {
	_, err := s.db.Exec(`DELETE FROM tcpguard_counters WHERE scope = ? AND key = ?`, scope, key)
	return err
}

func (s *SQLStateStore) getJSON(table, keyColumn, key string, out any) (bool, error) {
	var raw string
	query := fmt.Sprintf(`SELECT data FROM %s WHERE %s = ?`, table, keyColumn)
	err := s.db.QueryRow(query, key).Scan(&raw)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), out)
}

func (s *SQLStateStore) setJSON(table, keyColumn, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	query := fmt.Sprintf(`INSERT OR REPLACE INTO %s (%s, data) VALUES (?, ?)`, table, keyColumn)
	_, err = s.db.Exec(query, key, string(data))
	return err
}

var _ StateStore = (*SQLStateStore)(nil)
