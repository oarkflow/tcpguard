package tcpguard

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// CorrelationKey identifies an entity for event correlation.
type CorrelationKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// TimelineEntry is a single event in a correlated timeline.
type TimelineEntry struct {
	Event     SecurityEvent `json:"event"`
	RiskScore float64       `json:"risk_score"`
	Timestamp time.Time     `json:"timestamp"`
}

// AttackPath represents a correlated sequence of events forming an attack.
type AttackPath struct {
	ID         string           `json:"id"`
	Keys       []CorrelationKey `json:"keys"`
	Timeline   []TimelineEntry  `json:"timeline"`
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
	Severity   string           `json:"severity"`
	EventCount int              `json:"event_count"`
	Summary    string           `json:"summary"`
}

// SessionStory aggregates all events for a session into a narrative.
type SessionStory struct {
	SessionID      string          `json:"session_id"`
	UserID         string          `json:"user_id"`
	DeviceID       string          `json:"device_id"`
	Events         []TimelineEntry `json:"events"`
	RiskTrajectory []float64       `json:"risk_trajectory"`
	StartedAt      time.Time       `json:"started_at"`
	LastActivity   time.Time       `json:"last_activity"`
	MaxRiskScore   float64         `json:"max_risk_score"`
	Compromised    bool            `json:"compromised"`
}

// AttackPathFilter specifies criteria for querying attack paths.
type AttackPathFilter struct {
	Keys        []CorrelationKey
	Since       time.Time
	MinSeverity string
	Limit       int
}

// CorrelationEngine correlates security events across dimensions.
type CorrelationEngine interface {
	Correlate(ctx context.Context, event SecurityEvent) error
	GetTimeline(ctx context.Context, key CorrelationKey, since time.Time) ([]TimelineEntry, error)
	GetAttackPaths(ctx context.Context, filter AttackPathFilter) ([]AttackPath, error)
	GetSessionStory(ctx context.Context, sessionID string) (*SessionStory, error)
	Start(emitter EventEmitter)
	Stop()
}

// InMemoryCorrelationEngine is an in-memory implementation of CorrelationEngine.
type InMemoryCorrelationEngine struct {
	mu          sync.RWMutex
	index       map[string][]TimelineEntry // key: "type:value"
	attackPaths map[string]*AttackPath
	maxEntries  int
	maxAge      time.Duration
	stopCh      chan struct{}
	stopped     sync.Once
	unsubscribe func()
}

// NewInMemoryCorrelationEngine creates a new correlation engine.
func NewInMemoryCorrelationEngine(maxEntries int, maxAge time.Duration) *InMemoryCorrelationEngine {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	return &InMemoryCorrelationEngine{
		index:       make(map[string][]TimelineEntry),
		attackPaths: make(map[string]*AttackPath),
		maxEntries:  maxEntries,
		maxAge:      maxAge,
		stopCh:      make(chan struct{}),
	}
}

func indexKey(k CorrelationKey) string {
	return k.Type + ":" + k.Value
}

// extractKeys returns all non-empty correlation keys from an event.
func extractKeys(event SecurityEvent) []CorrelationKey {
	var keys []CorrelationKey
	if event.ClientIP != "" {
		keys = append(keys, CorrelationKey{Type: "ip", Value: event.ClientIP})
	}
	if event.SessionID != "" {
		keys = append(keys, CorrelationKey{Type: "session", Value: event.SessionID})
	}
	if event.UserID != "" {
		keys = append(keys, CorrelationKey{Type: "user", Value: event.UserID})
	}
	if event.DeviceID != "" {
		keys = append(keys, CorrelationKey{Type: "device", Value: event.DeviceID})
	}
	if event.TraceID != "" {
		keys = append(keys, CorrelationKey{Type: "trace", Value: event.TraceID})
	}
	return keys
}

// Correlate indexes a security event under all its correlation keys.
func (e *InMemoryCorrelationEngine) Correlate(_ context.Context, event SecurityEvent) error {
	keys := extractKeys(event)
	if len(keys) == 0 {
		return nil
	}

	entry := TimelineEntry{
		Event:     event,
		RiskScore: event.RiskScore,
		Timestamp: event.Timestamp,
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, k := range keys {
		ik := indexKey(k)
		entries := e.index[ik]
		entries = append(entries, entry)
		if len(entries) > e.maxEntries {
			entries = entries[len(entries)-e.maxEntries:]
		}
		e.index[ik] = entries
	}

	// Update or create attack paths for medium+ severity events.
	if sevRank(event.Severity) >= sevRank("medium") {
		e.updateAttackPath(event, keys, entry)
	}

	return nil
}

// updateAttackPath creates or updates an attack path. Must be called with mu held.
func (e *InMemoryCorrelationEngine) updateAttackPath(event SecurityEvent, keys []CorrelationKey, entry TimelineEntry) {
	// Use the first key as the primary attack path identifier.
	pathID := fmt.Sprintf("ap:%s:%s", keys[0].Type, keys[0].Value)

	ap, exists := e.attackPaths[pathID]
	if !exists {
		ap = &AttackPath{
			ID:        pathID,
			Keys:      keys,
			FirstSeen: entry.Timestamp,
			Severity:  event.Severity,
		}
		e.attackPaths[pathID] = ap
	}

	ap.Timeline = append(ap.Timeline, entry)
	ap.LastSeen = entry.Timestamp
	ap.EventCount = len(ap.Timeline)

	if sevRank(event.Severity) > sevRank(ap.Severity) {
		ap.Severity = event.Severity
	}

	// Merge keys.
	existing := make(map[string]bool)
	for _, k := range ap.Keys {
		existing[indexKey(k)] = true
	}
	for _, k := range keys {
		if !existing[indexKey(k)] {
			ap.Keys = append(ap.Keys, k)
		}
	}

	ap.Summary = fmt.Sprintf("%d events, severity %s, last: %s", ap.EventCount, ap.Severity, event.Type)
}

// GetTimeline returns timeline entries for a correlation key since the given time.
func (e *InMemoryCorrelationEngine) GetTimeline(_ context.Context, key CorrelationKey, since time.Time) ([]TimelineEntry, error) {
	e.mu.RLock()
	entries := e.index[indexKey(key)]
	e.mu.RUnlock()

	var filtered []TimelineEntry
	for _, ent := range entries {
		if !ent.Timestamp.Before(since) {
			filtered = append(filtered, ent)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})
	return filtered, nil
}

// GetAttackPaths returns attack paths matching the filter.
func (e *InMemoryCorrelationEngine) GetAttackPaths(_ context.Context, filter AttackPathFilter) ([]AttackPath, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	filterKeySet := make(map[string]bool)
	for _, k := range filter.Keys {
		filterKeySet[indexKey(k)] = true
	}

	var results []AttackPath
	for _, ap := range e.attackPaths {
		if !filter.Since.IsZero() && ap.LastSeen.Before(filter.Since) {
			continue
		}
		if filter.MinSeverity != "" && sevRank(ap.Severity) < sevRank(filter.MinSeverity) {
			continue
		}
		if len(filterKeySet) > 0 {
			match := false
			for _, k := range ap.Keys {
				if filterKeySet[indexKey(k)] {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		results = append(results, *ap)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].LastSeen.After(results[j].LastSeen)
	})

	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}
	return results, nil
}

// GetSessionStory builds a complete session narrative.
func (e *InMemoryCorrelationEngine) GetSessionStory(_ context.Context, sessionID string) (*SessionStory, error) {
	key := CorrelationKey{Type: "session", Value: sessionID}

	e.mu.RLock()
	entries := make([]TimelineEntry, len(e.index[indexKey(key)]))
	copy(entries, e.index[indexKey(key)])
	e.mu.RUnlock()

	if len(entries) == 0 {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	story := &SessionStory{
		SessionID:    sessionID,
		Events:       entries,
		StartedAt:    entries[0].Timestamp,
		LastActivity: entries[len(entries)-1].Timestamp,
	}

	for _, ent := range entries {
		story.RiskTrajectory = append(story.RiskTrajectory, ent.RiskScore)
		if ent.RiskScore > story.MaxRiskScore {
			story.MaxRiskScore = ent.RiskScore
		}
		if story.UserID == "" && ent.Event.UserID != "" {
			story.UserID = ent.Event.UserID
		}
		if story.DeviceID == "" && ent.Event.DeviceID != "" {
			story.DeviceID = ent.Event.DeviceID
		}
	}

	story.Compromised = story.MaxRiskScore > 0.70

	return story, nil
}

// Start subscribes to the event emitter and correlates incoming events.
func (e *InMemoryCorrelationEngine) Start(emitter EventEmitter) {
	ch := make(chan SecurityEvent, 256)
	e.unsubscribe = emitter.Subscribe(ch)

	// Start the event processing goroutine.
	go func() {
		for {
			select {
			case <-e.stopCh:
				return
			case event, ok := <-ch:
				if !ok {
					return
				}
				_ = e.Correlate(context.Background(), event)
			}
		}
	}()

	// Start the cleanup goroutine.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-e.stopCh:
				return
			case <-ticker.C:
				e.cleanup()
			}
		}
	}()
}

// Stop shuts down the correlation engine.
func (e *InMemoryCorrelationEngine) Stop() {
	e.stopped.Do(func() {
		close(e.stopCh)
		if e.unsubscribe != nil {
			e.unsubscribe()
		}
	})
}

// cleanup removes entries older than maxAge.
func (e *InMemoryCorrelationEngine) cleanup() {
	cutoff := time.Now().Add(-e.maxAge)

	e.mu.Lock()
	defer e.mu.Unlock()

	for key, entries := range e.index {
		// Find the first entry that is not expired.
		idx := sort.Search(len(entries), func(i int) bool {
			return !entries[i].Timestamp.Before(cutoff)
		})
		if idx == len(entries) {
			delete(e.index, key)
		} else if idx > 0 {
			e.index[key] = entries[idx:]
		}
	}

	for id, ap := range e.attackPaths {
		if ap.LastSeen.Before(cutoff) {
			delete(e.attackPaths, id)
		}
	}
}
