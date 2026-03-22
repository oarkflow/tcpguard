package tcpguard

import (
	"context"
	"time"
)

// EventIngestionService defines the contract for a future event ingestion service
// (e.g., consuming from Kafka or NATS).
type EventIngestionService interface {
	Ingest(ctx context.Context, events []SecurityEvent) error
	IngestRaw(ctx context.Context, source string, data []byte) error
	HealthCheck() error
}

// DetectionStreamProcessor defines the contract for a future real-time stream
// processing service that runs detectors over incoming events.
type DetectionStreamProcessor interface {
	Start(ctx context.Context) error
	Stop() error
	RegisterDetector(name string, fn DetectorFunc) error
	HealthCheck() error
}

// DetectorFunc is a function that evaluates an event against recent history
// and returns any detection results.
type DetectorFunc func(event SecurityEvent, history []SecurityEvent) []DetectionResult

// DetectionResult represents the output of a detector.
type DetectionResult struct {
	Type            string         `json:"type"`
	Severity        string         `json:"severity"`
	Confidence      float64        `json:"confidence"`
	Details         map[string]any `json:"details"`
	SuggestedAction *Action        `json:"suggested_action,omitempty"`
}

// SecurityAdminService defines the contract for a future admin console backend
// providing dashboard, policy, playbook, and entity management.
type SecurityAdminService interface {
	// Dashboard
	GetDashboardSummary(ctx context.Context) (*DashboardSummary, error)

	// Policy management
	GetPolicies(ctx context.Context) ([]Policy, error)
	UpdatePolicy(ctx context.Context, policy *Policy) error

	// Playbook management
	GetPlaybooks(ctx context.Context) ([]Playbook, error)
	UpdatePlaybook(ctx context.Context, playbook *Playbook) error

	// Entity management
	GetEntityStatus(ctx context.Context, key CorrelationKey) (*EntityStatus, error)
	BlockEntity(ctx context.Context, key CorrelationKey, duration time.Duration, reason string) error
	UnblockEntity(ctx context.Context, key CorrelationKey) error
}

// DashboardSummary provides a high-level overview of the security posture.
type DashboardSummary struct {
	ActiveIncidents    int               `json:"active_incidents"`
	TotalEventsLast24h int               `json:"total_events_last_24h"`
	TopAttackTypes     []AttackTypeSummary `json:"top_attack_types"`
	RiskDistribution   map[string]int    `json:"risk_distribution"`
	RecentDecisions    []SecurityEvent   `json:"recent_decisions"`
	BlockedEntities    int               `json:"blocked_entities"`
}

// AttackTypeSummary summarizes a specific attack type.
type AttackTypeSummary struct {
	Type     string    `json:"type"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// EntityStatus represents the current status of a tracked entity.
type EntityStatus struct {
	Key        CorrelationKey `json:"key"`
	Blocked    bool           `json:"blocked"`
	RiskScore  float64        `json:"risk_score"`
	EventCount int            `json:"event_count"`
	LastSeen   time.Time      `json:"last_seen"`
	Incidents  []string       `json:"incidents"`
}
