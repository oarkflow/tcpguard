package tcpguard

import (
	"sync"
	"time"
)

type DetectionLedger struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]*DetectionEvent
}

type DetectionEvent struct {
	ClientIP string          `json:"clientIP"`
	Endpoint string          `json:"endpoint"`
	Findings []AttackFinding `json:"findings"`
	Recorded time.Time       `json:"recorded"`
}

type DetectionSummary struct {
	ActiveAttacks map[string]int `json:"activeAttacks"`
	ActiveIPs     int            `json:"activeIPs"`
	TotalFindings int            `json:"totalFindings"`
	LastUpdated   time.Time      `json:"lastUpdated"`
}

func NewDetectionLedger(ttl time.Duration) *DetectionLedger {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &DetectionLedger{
		ttl:     ttl,
		entries: make(map[string]*DetectionEvent),
	}
}

func (l *DetectionLedger) Record(event DetectionEvent) {
	if event.ClientIP == "" || len(event.Findings) == 0 {
		return
	}
	event.Recorded = time.Now()
	l.mu.Lock()
	l.entries[event.ClientIP] = &event
	l.mu.Unlock()
}

func (l *DetectionLedger) Snapshot() []DetectionEvent {
	now := time.Now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	var events []DetectionEvent
	for _, entry := range l.entries {
		if now.Sub(entry.Recorded) > l.ttl {
			continue
		}
		events = append(events, *entry)
	}
	return events
}

func (l *DetectionLedger) Cleanup() {
	now := time.Now()
	l.mu.Lock()
	for ip, entry := range l.entries {
		if now.Sub(entry.Recorded) > l.ttl {
			delete(l.entries, ip)
		}
	}
	l.mu.Unlock()
}

func (l *DetectionLedger) Summary() DetectionSummary {
	summary := DetectionSummary{
		ActiveAttacks: make(map[string]int),
	}
	events := l.Snapshot()
	summary.ActiveIPs = len(events)
	for _, ev := range events {
		for _, finding := range ev.Findings {
			summary.ActiveAttacks[finding.Name]++
			summary.TotalFindings++
			if findingTime := ev.Recorded; findingTime.After(summary.LastUpdated) {
				summary.LastUpdated = findingTime
			}
		}
	}
	return summary
}
