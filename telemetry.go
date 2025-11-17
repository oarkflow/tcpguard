package tcpguard

import (
    "sync"
    "time"
)

type TelemetryStore struct {
    mu   sync.RWMutex
    ttl  time.Duration
    data map[string]*telemetryEntry
}

type telemetryEntry struct {
    metrics map[string]float64
    expires time.Time
}

func NewTelemetryStore(ttl time.Duration) *TelemetryStore {
    if ttl <= 0 {
        ttl = 5 * time.Minute
    }
    return &TelemetryStore{ttl: ttl, data: make(map[string]*telemetryEntry)}
}

func (s *TelemetryStore) Ingest(ip string, metrics map[string]float64) {
    if ip == "" || len(metrics) == 0 {
        return
    }
    s.mu.Lock()
    defer s.mu.Unlock()

    entry, exists := s.data[ip]
    if !exists {
        entry = &telemetryEntry{metrics: make(map[string]float64)}
        s.data[ip] = entry
    }
    for k, v := range metrics {
        entry.metrics[k] = v
    }
    entry.expires = time.Now().Add(s.ttl)
}

func (s *TelemetryStore) Snapshot(ip string) map[string]float64 {
    if ip == "" {
        return nil
    }
    s.mu.RLock()
    entry, exists := s.data[ip]
    s.mu.RUnlock()
    if !exists || time.Now().After(entry.expires) {
        s.mu.Lock()
        if s.data[ip] == entry {
            delete(s.data, ip)
        }
        s.mu.Unlock()
        return nil
    }
    snapshot := make(map[string]float64, len(entry.metrics))
    for k, v := range entry.metrics {
        snapshot[k] = v
    }
    return snapshot
}

func (s *TelemetryStore) Cleanup() {
    now := time.Now()
    s.mu.Lock()
    defer s.mu.Unlock()
    for ip, entry := range s.data {
        if now.After(entry.expires) {
            delete(s.data, ip)
        }
    }
}
