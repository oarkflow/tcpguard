package tcpguard

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Incident represents a security incident being investigated.
type Incident struct {
	ID            string          `json:"id"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	Severity      string          `json:"severity"`
	Status        string          `json:"status"` // open, investigating, resolved, closed
	AttackPathIDs []string        `json:"attack_path_ids"`
	EventIDs      []string        `json:"event_ids"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	ResolvedAt    *time.Time      `json:"resolved_at,omitempty"`
	AssignedTo    string          `json:"assigned_to,omitempty"`
	Notes         []IncidentNote  `json:"notes"`
	Tags          []string        `json:"tags"`
	RootEntity    *CorrelationKey `json:"root_entity,omitempty"`
}

// IncidentNote is a note attached to an incident.
type IncidentNote struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// IncidentFilter specifies criteria for listing incidents.
type IncidentFilter struct {
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	AssignedTo string   `json:"assigned_to"`
	Since      time.Time `json:"since"`
	Tags       []string `json:"tags"`
	Limit      int      `json:"limit"`
}

// IncidentUpdate represents a partial update to an incident.
type IncidentUpdate struct {
	Title       *string       `json:"title,omitempty"`
	Description *string       `json:"description,omitempty"`
	Severity    *string       `json:"severity,omitempty"`
	Status      *string       `json:"status,omitempty"`
	AssignedTo  *string       `json:"assigned_to,omitempty"`
	AddTags     []string      `json:"add_tags,omitempty"`
	RemoveTags  []string      `json:"remove_tags,omitempty"`
	Note        *IncidentNote `json:"note,omitempty"`
}

// EvidenceExport bundles all evidence for an incident.
type EvidenceExport struct {
	Incident    *Incident       `json:"incident"`
	AttackPaths []AttackPath    `json:"attack_paths"`
	Timeline    []TimelineEntry `json:"timeline"`
	Events      []SecurityEvent `json:"events"`
	ExportedAt  time.Time       `json:"exported_at"`
}

// InvestigationService defines operations for security investigation.
type InvestigationService interface {
	QueryTimeline(ctx context.Context, key CorrelationKey, since, until time.Time) ([]TimelineEntry, error)
	SearchEntities(ctx context.Context, query string) ([]CorrelationKey, error)
	CreateIncident(ctx context.Context, incident *Incident) (*Incident, error)
	GetIncident(ctx context.Context, id string) (*Incident, error)
	UpdateIncident(ctx context.Context, id string, update *IncidentUpdate) (*Incident, error)
	ListIncidents(ctx context.Context, filter IncidentFilter) ([]Incident, error)
	ExportEvidence(ctx context.Context, incidentID string) (*EvidenceExport, error)
}

// InMemoryInvestigationService is an in-memory implementation of InvestigationService.
type InMemoryInvestigationService struct {
	mu          sync.RWMutex
	incidents   map[string]*Incident
	correlation CorrelationEngine
	events      EventEmitter
}

// NewInMemoryInvestigationService creates a new InMemoryInvestigationService.
func NewInMemoryInvestigationService(correlation CorrelationEngine, events EventEmitter) *InMemoryInvestigationService {
	return &InMemoryInvestigationService{
		incidents:   make(map[string]*Incident),
		correlation: correlation,
		events:      events,
	}
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *InMemoryInvestigationService) QueryTimeline(ctx context.Context, key CorrelationKey, since, until time.Time) ([]TimelineEntry, error) {
	entries, err := s.correlation.GetTimeline(ctx, key, since)
	if err != nil {
		return nil, err
	}
	if until.IsZero() {
		return entries, nil
	}
	filtered := make([]TimelineEntry, 0, len(entries))
	for _, e := range entries {
		if !e.Timestamp.After(until) {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

func (s *InMemoryInvestigationService) SearchEntities(ctx context.Context, query string) ([]CorrelationKey, error) {
	q := strings.ToLower(query)
	// Search across known entity types
	entityTypes := []string{"ip", "user", "session", "device", "path"}
	var results []CorrelationKey
	seen := make(map[string]bool)

	for _, typ := range entityTypes {
		key := CorrelationKey{Type: typ, Value: query}
		timeline, err := s.correlation.GetTimeline(ctx, key, time.Time{})
		if err != nil {
			continue
		}
		if len(timeline) > 0 {
			k := typ + ":" + query
			if !seen[k] {
				seen[k] = true
				results = append(results, key)
			}
		}
	}

	// Also search attack paths for matching keys
	paths, err := s.correlation.GetAttackPaths(ctx, AttackPathFilter{Limit: 100})
	if err == nil {
		for _, p := range paths {
			for _, k := range p.Keys {
				composite := k.Type + ":" + k.Value
				if seen[composite] {
					continue
				}
				if strings.Contains(strings.ToLower(k.Value), q) || strings.Contains(strings.ToLower(k.Type), q) {
					seen[composite] = true
					results = append(results, k)
				}
			}
		}
	}

	return results, nil
}

func (s *InMemoryInvestigationService) CreateIncident(ctx context.Context, incident *Incident) (*Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	incident.ID = generateID()
	incident.CreatedAt = now
	incident.UpdatedAt = now
	if incident.Status == "" {
		incident.Status = "open"
	}
	if incident.Notes == nil {
		incident.Notes = []IncidentNote{}
	}
	if incident.Tags == nil {
		incident.Tags = []string{}
	}
	if incident.AttackPathIDs == nil {
		incident.AttackPathIDs = []string{}
	}
	if incident.EventIDs == nil {
		incident.EventIDs = []string{}
	}

	stored := *incident
	s.incidents[incident.ID] = &stored

	result := stored
	return &result, nil
}

func (s *InMemoryInvestigationService) GetIncident(ctx context.Context, id string) (*Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inc, ok := s.incidents[id]
	if !ok {
		return nil, fmt.Errorf("incident not found: %s", id)
	}
	result := *inc
	return &result, nil
}

func (s *InMemoryInvestigationService) UpdateIncident(ctx context.Context, id string, update *IncidentUpdate) (*Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inc, ok := s.incidents[id]
	if !ok {
		return nil, fmt.Errorf("incident not found: %s", id)
	}

	now := time.Now()

	if update.Title != nil {
		inc.Title = *update.Title
	}
	if update.Description != nil {
		inc.Description = *update.Description
	}
	if update.Severity != nil {
		inc.Severity = *update.Severity
	}
	if update.Status != nil {
		inc.Status = *update.Status
		if *update.Status == "resolved" || *update.Status == "closed" {
			inc.ResolvedAt = &now
		}
	}
	if update.AssignedTo != nil {
		inc.AssignedTo = *update.AssignedTo
	}

	for _, tag := range update.AddTags {
		found := false
		for _, t := range inc.Tags {
			if t == tag {
				found = true
				break
			}
		}
		if !found {
			inc.Tags = append(inc.Tags, tag)
		}
	}

	for _, rem := range update.RemoveTags {
		for i, t := range inc.Tags {
			if t == rem {
				inc.Tags = append(inc.Tags[:i], inc.Tags[i+1:]...)
				break
			}
		}
	}

	if update.Note != nil {
		note := *update.Note
		note.ID = generateID()
		note.CreatedAt = now
		inc.Notes = append(inc.Notes, note)
	}

	inc.UpdatedAt = now

	result := *inc
	return &result, nil
}

func (s *InMemoryInvestigationService) ListIncidents(ctx context.Context, filter IncidentFilter) ([]Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Incident
	for _, inc := range s.incidents {
		if filter.Status != "" && inc.Status != filter.Status {
			continue
		}
		if filter.Severity != "" && inc.Severity != filter.Severity {
			continue
		}
		if filter.AssignedTo != "" && inc.AssignedTo != filter.AssignedTo {
			continue
		}
		if !filter.Since.IsZero() && inc.CreatedAt.Before(filter.Since) {
			continue
		}
		if len(filter.Tags) > 0 {
			matched := false
			for _, ft := range filter.Tags {
				for _, it := range inc.Tags {
					if ft == it {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}
		results = append(results, *inc)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results, nil
}

func (s *InMemoryInvestigationService) ExportEvidence(ctx context.Context, incidentID string) (*EvidenceExport, error) {
	s.mu.RLock()
	inc, ok := s.incidents[incidentID]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}
	incCopy := *inc
	// Deep copy slices to avoid race conditions
	incCopy.AttackPathIDs = make([]string, len(inc.AttackPathIDs))
	copy(incCopy.AttackPathIDs, inc.AttackPathIDs)
	incCopy.EventIDs = make([]string, len(inc.EventIDs))
	copy(incCopy.EventIDs, inc.EventIDs)
	incCopy.Tags = make([]string, len(inc.Tags))
	copy(incCopy.Tags, inc.Tags)
	incCopy.Notes = make([]IncidentNote, len(inc.Notes))
	copy(incCopy.Notes, inc.Notes)
	s.mu.RUnlock()

	export := &EvidenceExport{
		Incident:   &incCopy,
		ExportedAt: time.Now(),
	}

	// Gather attack paths
	if len(incCopy.AttackPathIDs) > 0 {
		paths, err := s.correlation.GetAttackPaths(ctx, AttackPathFilter{Limit: 1000})
		if err == nil {
			idSet := make(map[string]bool, len(incCopy.AttackPathIDs))
			for _, id := range incCopy.AttackPathIDs {
				idSet[id] = true
			}
			for _, p := range paths {
				if idSet[p.ID] {
					export.AttackPaths = append(export.AttackPaths, p)
				}
			}
		}
	}

	// Gather timeline from root entity
	if incCopy.RootEntity != nil {
		timeline, err := s.correlation.GetTimeline(ctx, *incCopy.RootEntity, incCopy.CreatedAt.Add(-24*time.Hour))
		if err == nil {
			export.Timeline = timeline
		}
	}

	// Gather events
	if len(incCopy.EventIDs) > 0 && s.events != nil {
		events, err := s.events.Query(ctx, EventFilter{
			Since: incCopy.CreatedAt.Add(-24 * time.Hour),
			Limit: 1000,
		})
		if err == nil {
			idSet := make(map[string]bool, len(incCopy.EventIDs))
			for _, id := range incCopy.EventIDs {
				idSet[id] = true
			}
			for _, e := range events {
				if idSet[e.ID] {
					export.Events = append(export.Events, e)
				}
			}
		}
	}

	return export, nil
}
