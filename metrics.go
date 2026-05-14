package tcpguard

import (
	"context"
	"sync"
	"time"
)

type MetricsSnapshot struct {
	Decisions        map[DecisionEffect]int64 `json:"decisions"`
	Severities       map[Severity]int64       `json:"severities"`
	MatchedRules     map[string]int64         `json:"matched_rules"`
	Detectors        map[string]int64         `json:"detectors"`
	DetectorErrors   map[string]int64         `json:"detector_errors"`
	Actions          map[string]int64         `json:"actions"`
	ActionErrors     map[string]int64         `json:"action_errors"`
	Reloads          int64                    `json:"reloads"`
	ReloadErrors     int64                    `json:"reload_errors"`
	DecisionDuration time.Duration            `json:"decision_duration"`
	DetectorDuration time.Duration            `json:"detector_duration"`
	ActionDuration   time.Duration            `json:"action_duration"`
	ReloadDuration   time.Duration            `json:"reload_duration"`
}

type MemoryMetrics struct {
	mu       sync.Mutex
	snapshot MetricsSnapshot
}

func NewMemoryMetrics() *MemoryMetrics {
	return &MemoryMetrics{snapshot: MetricsSnapshot{
		Decisions:      map[DecisionEffect]int64{},
		Severities:     map[Severity]int64{},
		MatchedRules:   map[string]int64{},
		Detectors:      map[string]int64{},
		DetectorErrors: map[string]int64{},
		Actions:        map[string]int64{},
		ActionErrors:   map[string]int64{},
	}}
}

func (m *MemoryMetrics) RecordDecision(_ context.Context, _ *Context, decision Decision, duration time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot.Decisions[decision.Effect]++
	m.snapshot.Severities[decision.Severity]++
	for _, rule := range decision.MatchedRules {
		m.snapshot.MatchedRules[rule]++
	}
	m.snapshot.DecisionDuration += duration
}

func (m *MemoryMetrics) RecordDetector(_ context.Context, id string, _ int, err error, duration time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot.Detectors[id]++
	if err != nil {
		m.snapshot.DetectorErrors[id]++
	}
	m.snapshot.DetectorDuration += duration
}

func (m *MemoryMetrics) RecordAction(_ context.Context, _ *Context, _ Decision, result ActionResult, duration time.Duration) {
	if m == nil {
		return
	}
	actionType := firstNonEmpty(result.Type, result.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot.Actions[actionType]++
	if result.Status == "error" || result.Error != "" {
		m.snapshot.ActionErrors[actionType]++
	}
	m.snapshot.ActionDuration += duration
}

func (m *MemoryMetrics) RecordReload(_ context.Context, ok bool, duration time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot.Reloads++
	if !ok {
		m.snapshot.ReloadErrors++
	}
	m.snapshot.ReloadDuration += duration
}

func (m *MemoryMetrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.snapshot
	out.Decisions = copyDecisionCounts(m.snapshot.Decisions)
	out.Severities = copySeverityCounts(m.snapshot.Severities)
	out.MatchedRules = copyStringCounts(m.snapshot.MatchedRules)
	out.Detectors = copyStringCounts(m.snapshot.Detectors)
	out.DetectorErrors = copyStringCounts(m.snapshot.DetectorErrors)
	out.Actions = copyStringCounts(m.snapshot.Actions)
	out.ActionErrors = copyStringCounts(m.snapshot.ActionErrors)
	return out
}

func copyDecisionCounts(in map[DecisionEffect]int64) map[DecisionEffect]int64 {
	out := make(map[DecisionEffect]int64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copySeverityCounts(in map[Severity]int64) map[Severity]int64 {
	out := make(map[Severity]int64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyStringCounts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
