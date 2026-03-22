package tcpguard

import (
	"sync"
	"time"
)

// StateStore extends CounterStore with advanced state management capabilities
// for sliding windows, token revocation, device trust, session state, and account locks.
type StateStore interface {
	CounterStore

	// SlidingIncrement adds a timestamp to a sliding window for the given key.
	SlidingIncrement(key string, window time.Duration) error
	// SlidingCount returns the number of events within the sliding window.
	SlidingCount(key string, window time.Duration) (int, error)

	// RevokeToken marks a token as revoked until the given expiry.
	RevokeToken(token string, expiry time.Time) error
	// IsTokenRevoked checks whether a token has been revoked.
	IsTokenRevoked(token string) (bool, error)

	// GetDeviceTrust retrieves trust information for a device fingerprint.
	GetDeviceTrust(fingerprint string) (*DeviceTrust, error)
	// SetDeviceTrust stores trust information for a device fingerprint.
	SetDeviceTrust(fingerprint string, trust *DeviceTrust) error

	// GetSessionState retrieves the session state for a session ID.
	GetSessionState(sessionID string) (*SessionState, error)
	// SetSessionState stores the session state for a session ID.
	SetSessionState(sessionID string, state *SessionState) error
	// DeleteSessionState removes the session state for a session ID.
	DeleteSessionState(sessionID string) error

	// GetAccountLock retrieves the lock state for an account.
	GetAccountLock(accountID string) (*AccountLockState, error)
	// SetAccountLock stores the lock state for an account.
	SetAccountLock(accountID string, lock *AccountLockState) error
	// DeleteAccountLock removes the lock state for an account.
	DeleteAccountLock(accountID string) error

	// GetAccountLockState is an alias for GetAccountLock for backward compatibility.
	GetAccountLockState(accountID string) (*AccountLockState, error)
}

// DeviceTrust holds trust metadata for a device fingerprint.
type DeviceTrust struct {
	Fingerprint string    `json:"fingerprint"`
	UserID      string    `json:"userId"`
	TrustLevel  float64   `json:"trustLevel"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	Verified    bool      `json:"verified"`
}

// SessionState holds the current state of a user session.
type SessionState struct {
	SessionID   string    `json:"sessionId"`
	UserID      string    `json:"userId"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"userAgent"`
	CreatedAt   time.Time `json:"createdAt"`
	LastActive  time.Time `json:"lastActive"`
	RiskLevel   float64   `json:"riskLevel"`
	Challenged  bool      `json:"challenged"`
	MFAVerified bool      `json:"mfaVerified"`
}

// AccountLockState holds lock information for a user account.
type AccountLockState struct {
	AccountID    string    `json:"accountId"`
	Locked       bool      `json:"locked"`
	LockedAt     time.Time `json:"lockedAt"`
	LockedUntil  time.Time `json:"lockedUntil"`
	UnlockAt     time.Time `json:"unlockAt"`
	FailedCount  int       `json:"failedCount"`
	LastFailedAt time.Time `json:"lastFailedAt"`
	Reason       string    `json:"reason"`
}


// InMemoryStateStore implements StateStore with in-memory storage.
// It embeds *InMemoryCounterStore for base CounterStore functionality
// and uses a separate mutex for the extended state maps.
type InMemoryStateStore struct {
	*InMemoryCounterStore

	mu             sync.RWMutex
	slidingWindows map[string][]time.Time
	revokedTokens  map[string]time.Time
	deviceTrust    map[string]*DeviceTrust
	sessionStates  map[string]*SessionState
	accountLocks   map[string]*AccountLockState

	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	stopped         sync.Once
}

// NewInMemoryStateStore creates a new InMemoryStateStore with a background cleanup goroutine.
func NewInMemoryStateStore() *InMemoryStateStore {
	s := &InMemoryStateStore{
		InMemoryCounterStore: NewInMemoryCounterStore(),
		slidingWindows:       make(map[string][]time.Time),
		revokedTokens:        make(map[string]time.Time),
		deviceTrust:          make(map[string]*DeviceTrust),
		sessionStates:        make(map[string]*SessionState),
		accountLocks:         make(map[string]*AccountLockState),
		cleanupInterval:      5 * time.Minute,
		stopCleanup:          make(chan struct{}),
	}
	go s.startStateCleanup()
	return s
}

func (s *InMemoryStateStore) startStateCleanup() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupState()
		case <-s.stopCleanup:
			return
		}
	}
}

func (s *InMemoryStateStore) cleanupState() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Remove expired revoked tokens.
	for token, expiry := range s.revokedTokens {
		if now.After(expiry) {
			delete(s.revokedTokens, token)
		}
	}

	// Prune sliding window entries older than 1 hour (conservative max window).
	maxAge := time.Hour
	for key, timestamps := range s.slidingWindows {
		cutoff := now.Add(-maxAge)
		pruned := timestamps[:0]
		for _, t := range timestamps {
			if t.After(cutoff) {
				pruned = append(pruned, t)
			}
		}
		if len(pruned) == 0 {
			delete(s.slidingWindows, key)
		} else {
			s.slidingWindows[key] = pruned
		}
	}

	// Remove expired account locks.
	for id, lock := range s.accountLocks {
		if lock.Locked && !lock.UnlockAt.IsZero() && now.After(lock.UnlockAt) {
			delete(s.accountLocks, id)
		}
	}

	// Remove expired sessions (absolute TTL: 24h, idle timeout: 30min).
	for id, session := range s.sessionStates {
		if now.Sub(session.CreatedAt) > 24*time.Hour || now.Sub(session.LastActive) > 30*time.Minute {
			delete(s.sessionStates, id)
		}
	}
}

// StopStateCleanup stops the background cleanup goroutine for extended state.
func (s *InMemoryStateStore) StopStateCleanup() {
	s.stopped.Do(func() {
		close(s.stopCleanup)
	})
}

// maxSlidingWindowEntries is the maximum number of timestamps per sliding window key
// to prevent memory exhaustion during sustained attacks.
const maxSlidingWindowEntries = 10_000

// SlidingIncrement adds the current timestamp to the sliding window for the given key.
// If the window exceeds maxSlidingWindowEntries, further entries are dropped.
func (s *InMemoryStateStore) SlidingIncrement(key string, window time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	existing := s.slidingWindows[key]
	// Prune expired entries while appending.
	pruned := existing[:0]
	for _, t := range existing {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	// Cap entries to prevent memory exhaustion
	if len(pruned) >= maxSlidingWindowEntries {
		s.slidingWindows[key] = pruned
		return nil
	}
	s.slidingWindows[key] = append(pruned, now)
	return nil
}

// SlidingCount returns the number of events within the sliding window for the given key.
func (s *InMemoryStateStore) SlidingCount(key string, window time.Duration) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	count := 0
	for _, t := range s.slidingWindows[key] {
		if t.After(cutoff) {
			count++
		}
	}
	return count, nil
}

// RevokeToken marks a token as revoked until the given expiry time.
func (s *InMemoryStateStore) RevokeToken(token string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedTokens[token] = expiry
	return nil
}

// IsTokenRevoked checks whether a token has been revoked and is still within its expiry.
func (s *InMemoryStateStore) IsTokenRevoked(token string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiry, exists := s.revokedTokens[token]
	if !exists {
		return false, nil
	}
	if time.Now().After(expiry) {
		return false, nil
	}
	return true, nil
}

// GetDeviceTrust retrieves trust information for a device fingerprint.
func (s *InMemoryStateStore) GetDeviceTrust(fingerprint string) (*DeviceTrust, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	trust, exists := s.deviceTrust[fingerprint]
	if !exists {
		return nil, nil
	}
	return trust, nil
}

// SetDeviceTrust stores trust information for a device fingerprint.
func (s *InMemoryStateStore) SetDeviceTrust(fingerprint string, trust *DeviceTrust) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceTrust[fingerprint] = trust
	return nil
}

// GetSessionState retrieves the session state for a session ID.
func (s *InMemoryStateStore) GetSessionState(sessionID string) (*SessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.sessionStates[sessionID]
	if !exists {
		return nil, nil
	}
	return state, nil
}

// SetSessionState stores the session state for a session ID.
func (s *InMemoryStateStore) SetSessionState(sessionID string, state *SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionStates[sessionID] = state
	return nil
}

// DeleteSessionState removes the session state for a session ID.
func (s *InMemoryStateStore) DeleteSessionState(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessionStates, sessionID)
	return nil
}

// GetAccountLock retrieves the lock state for an account.
func (s *InMemoryStateStore) GetAccountLock(accountID string) (*AccountLockState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	lock, exists := s.accountLocks[accountID]
	if !exists {
		return nil, nil
	}
	return lock, nil
}

// SetAccountLock stores the lock state for an account.
func (s *InMemoryStateStore) SetAccountLock(accountID string, lock *AccountLockState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountLocks[accountID] = lock
	return nil
}

// DeleteAccountLock removes the lock state for an account.
func (s *InMemoryStateStore) DeleteAccountLock(accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accountLocks, accountID)
	return nil
}

// GetAccountLockState is an alias for GetAccountLock for backward compatibility.
func (s *InMemoryStateStore) GetAccountLockState(accountID string) (*AccountLockState, error) {
	return s.GetAccountLock(accountID)
}

// Ensure InMemoryStateStore implements StateStore.
var _ StateStore = (*InMemoryStateStore)(nil)
