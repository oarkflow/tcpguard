package tcpguard

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// SQLEventEmitter stores security and audit events in SQL and fans them out to
// in-process subscribers. Use it when audit history must survive restarts.
type SQLEventEmitter struct {
	db *sqlx.DB

	mu          sync.RWMutex
	subscribers map[int]chan<- SecurityEvent
	nextSubID   int
}

func NewSQLEventEmitter(db *sqlx.DB) (*SQLEventEmitter, error) {
	emitter := &SQLEventEmitter{
		db:          db,
		subscribers: make(map[int]chan<- SecurityEvent),
	}
	if err := emitter.createTables(); err != nil {
		return nil, err
	}
	return emitter, nil
}

func (e *SQLEventEmitter) createTables() error {
	_, err := e.db.Exec(`
	CREATE TABLE IF NOT EXISTS tcpguard_security_events (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL,
		request_id TEXT,
		trace_id TEXT,
		session_id TEXT,
		device_id TEXT,
		user_id TEXT,
		client_ip TEXT,
		path TEXT,
		method TEXT,
		decision TEXT,
		risk_score REAL,
		event_json TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_tcpguard_security_events_timestamp ON tcpguard_security_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_tcpguard_security_events_type ON tcpguard_security_events(type);
	CREATE INDEX IF NOT EXISTS idx_tcpguard_security_events_user_id ON tcpguard_security_events(user_id);
	CREATE INDEX IF NOT EXISTS idx_tcpguard_security_events_client_ip ON tcpguard_security_events(client_ip);
	`)
	return err
}

func (e *SQLEventEmitter) Emit(ctx context.Context, event SecurityEvent) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO tcpguard_security_events
			(id, type, severity, timestamp, request_id, trace_id, session_id, device_id, user_id, client_ip, path, method, decision, risk_score, event_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Type, event.Severity, event.Timestamp, nullEmpty(event.RequestID), nullEmpty(event.TraceID),
		nullEmpty(event.SessionID), nullEmpty(event.DeviceID), nullEmpty(event.UserID), nullEmpty(event.ClientIP),
		nullEmpty(event.Path), nullEmpty(event.Method), nullEmpty(event.Decision), event.RiskScore, string(data))
	if err != nil {
		return err
	}

	e.mu.RLock()
	subs := make([]chan<- SecurityEvent, 0, len(e.subscribers))
	for _, ch := range e.subscribers {
		subs = append(subs, ch)
	}
	e.mu.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- event:
		default:
		}
	}
	return nil
}

func (e *SQLEventEmitter) Query(ctx context.Context, filter EventFilter) ([]SecurityEvent, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}

	rows, err := e.db.QueryContext(ctx, `SELECT event_json FROM tcpguard_security_events ORDER BY timestamp DESC LIMIT ?`, limit*4)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]SecurityEvent, 0, limit)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var event SecurityEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return nil, err
		}
		if !matchesFilter(event, filter) {
			continue
		}
		events = append(events, event)
		if len(events) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (e *SQLEventEmitter) Subscribe(ch chan<- SecurityEvent) func() {
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

func nullEmpty(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

var _ EventEmitter = (*SQLEventEmitter)(nil)
