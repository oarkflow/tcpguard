package tcpguard

import (
	"sync"
	"time"
)

// InMemoryCounterStore implements CounterStore with in-memory storage
type InMemoryCounterStore struct {
	mu               sync.RWMutex
	globalRequests   map[string]*RequestCounter
	endpointRequests map[string]map[string]*RequestCounter
	bannedClients    map[string]*BanInfo
	actionCounters   map[string]*GenericCounter
	userSessions     map[string][]*SessionInfo
	cleanupInterval  time.Duration
	stopCleanup      chan struct{}
}

func NewInMemoryCounterStore() *InMemoryCounterStore {
	store := &InMemoryCounterStore{
		globalRequests:   make(map[string]*RequestCounter),
		endpointRequests: make(map[string]map[string]*RequestCounter),
		bannedClients:    make(map[string]*BanInfo),
		actionCounters:   make(map[string]*GenericCounter),
		userSessions:     make(map[string][]*SessionInfo),
		cleanupInterval:  5 * time.Minute, // Cleanup every 5 minutes
		stopCleanup:      make(chan struct{}),
	}
	go store.startCleanup()
	return store
}

func (s *InMemoryCounterStore) startCleanup() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

func (s *InMemoryCounterStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Cleanup expired global requests (older than 1 hour)
	for ip, counter := range s.globalRequests {
		if now.Sub(counter.LastReset) > time.Hour {
			delete(s.globalRequests, ip)
		}
	}

	// Cleanup expired endpoint requests
	for ip, endpoints := range s.endpointRequests {
		for endpoint, counter := range endpoints {
			if now.Sub(counter.LastReset) > time.Hour {
				delete(endpoints, endpoint)
			}
		}
		if len(endpoints) == 0 {
			delete(s.endpointRequests, ip)
		}
	}

	// Cleanup expired bans
	for ip, ban := range s.bannedClients {
		if !ban.Permanent && now.After(ban.Until) {
			delete(s.bannedClients, ip)
		}
	}

	// Cleanup old action counters (older than 1 hour)
	for key, counter := range s.actionCounters {
		if now.Sub(counter.First) > time.Hour {
			delete(s.actionCounters, key)
		}
	}

	// Cleanup old sessions (older than 24 hours)
	for userID, sessions := range s.userSessions {
		var validSessions []*SessionInfo
		for _, session := range sessions {
			if now.Sub(session.Created) < 24*time.Hour {
				validSessions = append(validSessions, session)
			}
		}
		if len(validSessions) == 0 {
			delete(s.userSessions, userID)
		} else {
			s.userSessions[userID] = validSessions
		}
	}
}

func (s *InMemoryCounterStore) StopCleanup() {
	close(s.stopCleanup)
}

func (s *InMemoryCounterStore) IncrementGlobal(ip string) (count int, lastReset time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	counter, exists := s.globalRequests[ip]
	if !exists || now.Sub(counter.LastReset) > time.Minute {
		s.globalRequests[ip] = &RequestCounter{
			Count:     1,
			LastReset: now,
		}
		return 1, now, nil
	}
	counter.Count++
	return counter.Count, counter.LastReset, nil
}

func (s *InMemoryCounterStore) GetGlobal(ip string) (*RequestCounter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counter, exists := s.globalRequests[ip]
	if !exists {
		return nil, nil
	}
	return counter, nil
}

func (s *InMemoryCounterStore) ResetGlobal(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.globalRequests, ip)
	return nil
}

func (s *InMemoryCounterStore) IncrementEndpoint(ip, endpoint string) (*RequestCounter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endpointRequests[ip] == nil {
		s.endpointRequests[ip] = make(map[string]*RequestCounter)
	}
	now := time.Now()
	counter, exists := s.endpointRequests[ip][endpoint]
	if !exists || now.Sub(counter.LastReset) > time.Minute {
		s.endpointRequests[ip][endpoint] = &RequestCounter{
			Count:     1,
			LastReset: now,
			Burst:     1,
		}
		return s.endpointRequests[ip][endpoint], nil
	}
	counter.Count++
	counter.Burst++
	return counter, nil
}

func (s *InMemoryCounterStore) GetEndpoint(ip, endpoint string) (*RequestCounter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.endpointRequests[ip] == nil {
		return nil, nil
	}
	counter, exists := s.endpointRequests[ip][endpoint]
	if !exists {
		return nil, nil
	}
	return counter, nil
}

func (s *InMemoryCounterStore) IncrementActionCounter(key string, window time.Duration) (count int, first time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	counter, exists := s.actionCounters[key]
	if !exists || (window > 0 && now.Sub(counter.First) > window) {
		s.actionCounters[key] = &GenericCounter{
			Count: 1,
			First: now,
		}
		return 1, now, nil
	}
	counter.Count++
	return counter.Count, counter.First, nil
}

func (s *InMemoryCounterStore) GetActionCounter(key string) (*GenericCounter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counter, exists := s.actionCounters[key]
	if !exists {
		return nil, nil
	}
	return counter, nil
}

func (s *InMemoryCounterStore) DeleteActionCounter(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.actionCounters, key)
	return nil
}

func (s *InMemoryCounterStore) GetBan(ip string) (*BanInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ban, exists := s.bannedClients[ip]
	if !exists {
		return nil, nil
	}
	return ban, nil
}

func (s *InMemoryCounterStore) SetBan(ip string, ban *BanInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bannedClients[ip] = ban
	return nil
}

func (s *InMemoryCounterStore) DeleteBan(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bannedClients, ip)
	return nil
}

func (s *InMemoryCounterStore) GetSessions(userID string) ([]*SessionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sessions, exists := s.userSessions[userID]
	if !exists {
		return nil, nil
	}
	return sessions, nil
}

func (s *InMemoryCounterStore) PutSessions(userID string, sessions []*SessionInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userSessions[userID] = sessions
	return nil
}

// HealthCheck performs a health check on the store
func (s *InMemoryCounterStore) HealthCheck() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Basic health check - ensure maps are accessible
	_ = len(s.globalRequests)
	_ = len(s.endpointRequests)
	_ = len(s.bannedClients)
	_ = len(s.actionCounters)
	_ = len(s.userSessions)

	return nil
}
