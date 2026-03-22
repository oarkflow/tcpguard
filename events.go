package tcpguard

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SecurityEvent represents a security-relevant event in the system.
type SecurityEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	Timestamp time.Time      `json:"timestamp"`
	RequestID string         `json:"request_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	DeviceID  string         `json:"device_id,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	ClientIP  string         `json:"client_ip,omitempty"`
	Path      string         `json:"path,omitempty"`
	Method    string         `json:"method,omitempty"`
	Verdict   *RiskVerdict   `json:"verdict,omitempty"`
	Decision  string         `json:"decision"`
	RiskScore float64        `json:"risk_score"`
	Details   map[string]any `json:"details,omitempty"`
}

// EventFilter specifies criteria for querying security events.
type EventFilter struct {
	Since       time.Time `json:"since,omitempty"`
	Until       time.Time `json:"until,omitempty"`
	Types       []string  `json:"types,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	DeviceID    string    `json:"device_id,omitempty"`
	TraceID     string    `json:"trace_id,omitempty"`
	MinSeverity string    `json:"min_severity,omitempty"`
	Limit       int       `json:"limit,omitempty"`
}

// EventEmitter provides event emission, querying, and subscription.
type EventEmitter interface {
	Emit(ctx context.Context, event SecurityEvent) error
	Query(ctx context.Context, filter EventFilter) ([]SecurityEvent, error)
	Subscribe(ch chan<- SecurityEvent) func()
}

// InMemoryEventEmitter implements EventEmitter with an in-memory ring buffer.
type InMemoryEventEmitter struct {
	mu          sync.RWMutex
	buffer      []SecurityEvent
	size        int
	head        int
	count       int
	subscribers map[int]chan<- SecurityEvent
	nextSubID   int
}

// NewInMemoryEventEmitter creates a new InMemoryEventEmitter with the given capacity.
func NewInMemoryEventEmitter(size int) *InMemoryEventEmitter {
	if size <= 0 {
		size = 10000
	}
	return &InMemoryEventEmitter{
		buffer:      make([]SecurityEvent, size),
		size:        size,
		subscribers: make(map[int]chan<- SecurityEvent),
	}
}

// Emit adds an event to the ring buffer and fans out to all subscribers (non-blocking).
func (e *InMemoryEventEmitter) Emit(ctx context.Context, event SecurityEvent) error {
	e.mu.Lock()
	// Write to ring buffer
	idx := (e.head + e.count) % e.size
	if e.count == e.size {
		// Buffer full: overwrite oldest, advance head
		e.buffer[e.head] = event
		e.head = (e.head + 1) % e.size
	} else {
		e.buffer[idx] = event
		e.count++
	}
	// Snapshot subscribers for fan-out outside lock
	subs := make([]chan<- SecurityEvent, 0, len(e.subscribers))
	for _, ch := range e.subscribers {
		subs = append(subs, ch)
	}
	e.mu.Unlock()

	// Non-blocking fan-out
	for _, ch := range subs {
		select {
		case ch <- event:
		default:
		}
	}
	return nil
}

// Query scans the ring buffer and returns events matching the filter.
func (e *InMemoryEventEmitter) Query(ctx context.Context, filter EventFilter) ([]SecurityEvent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []SecurityEvent
	limit := filter.Limit
	if limit <= 0 {
		limit = e.count
	}

	for i := 0; i < e.count; i++ {
		if len(results) >= limit {
			break
		}
		idx := (e.head + i) % e.size
		ev := e.buffer[idx]

		if !matchesFilter(ev, filter) {
			continue
		}
		results = append(results, ev)
	}
	return results, nil
}

// Subscribe registers a channel to receive emitted events. Returns an unsubscribe function.
func (e *InMemoryEventEmitter) Subscribe(ch chan<- SecurityEvent) func() {
	e.mu.Lock()
	id := e.nextSubID
	e.nextSubID++
	e.subscribers[id] = ch
	e.mu.Unlock()

	return func() {
		e.mu.Lock()
		delete(e.subscribers, id)
		e.mu.Unlock()
	}
}

// NewSecurityEvent creates a SecurityEvent with a generated UUID and current timestamp.
func NewSecurityEvent(eventType, severity string) SecurityEvent {
	return SecurityEvent{
		ID:        uuid.New().String(),
		Type:      eventType,
		Severity:  severity,
		Timestamp: time.Now(),
	}
}

// severityRank maps severity strings to numeric ranks for comparison.
var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func matchesFilter(ev SecurityEvent, f EventFilter) bool {
	if !f.Since.IsZero() && ev.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && ev.Timestamp.After(f.Until) {
		return false
	}
	if len(f.Types) > 0 {
		found := false
		for _, t := range f.Types {
			if ev.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.SessionID != "" && ev.SessionID != f.SessionID {
		return false
	}
	if f.UserID != "" && ev.UserID != f.UserID {
		return false
	}
	if f.ClientIP != "" && ev.ClientIP != f.ClientIP {
		return false
	}
	if f.DeviceID != "" && ev.DeviceID != f.DeviceID {
		return false
	}
	if f.TraceID != "" && ev.TraceID != f.TraceID {
		return false
	}
	if f.MinSeverity != "" {
		minRank, ok := severityRank[f.MinSeverity]
		if ok {
			evRank, ok2 := severityRank[ev.Severity]
			if !ok2 || evRank < minRank {
				return false
			}
		}
	}
	return true
}

// Ensure InMemoryEventEmitter implements EventEmitter.
var _ EventEmitter = (*InMemoryEventEmitter)(nil)
