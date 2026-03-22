package tcpguard

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PlaybookStep defines a single step within a playbook.
type PlaybookStep struct {
	ActionType  string         `json:"action_type"`
	Params      map[string]any `json:"params,omitempty"`
	Condition   string         `json:"condition,omitempty"`
	Description string         `json:"description"`
}

// Playbook defines an automated response sequence triggered by a security event.
type Playbook struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Trigger  string        `json:"trigger"`
	Severity string        `json:"severity"`
	Steps    []PlaybookStep `json:"steps"`
	Enabled  bool          `json:"enabled"`
	Cooldown time.Duration `json:"cooldown"`
}

// PlaybookExecution records the result of executing a playbook.
type PlaybookExecution struct {
	PlaybookID    string
	TriggerEvent  SecurityEvent
	StepsExecuted int
	StepsFailed   int
	StartedAt     time.Time
	CompletedAt   time.Time
	Results       []StepResult
}

// StepResult records the outcome of a single playbook step.
type StepResult struct {
	StepIndex  int
	ActionType string
	Success    bool
	Error      string
	Duration   time.Duration
}

// PlaybookRegistry manages and executes security playbooks.
type PlaybookRegistry interface {
	Register(playbook Playbook) error
	Unregister(id string) error
	Execute(ctx context.Context, event SecurityEvent, store StateStore) (*PlaybookExecution, error)
	List() []Playbook
}

const maxExecutionLog = 1000

// InMemoryPlaybookRegistry is an in-memory implementation of PlaybookRegistry.
type InMemoryPlaybookRegistry struct {
	mu            sync.RWMutex
	playbooks     map[string]*Playbook
	lastExecution map[string]time.Time
	executionLog  []PlaybookExecution
	actionReg     *ActionHandlerRegistry
}

// NewInMemoryPlaybookRegistry creates a new InMemoryPlaybookRegistry.
// actionReg may be nil if action dispatch is not needed.
func NewInMemoryPlaybookRegistry(actionReg *ActionHandlerRegistry) *InMemoryPlaybookRegistry {
	return &InMemoryPlaybookRegistry{
		playbooks:     make(map[string]*Playbook),
		lastExecution: make(map[string]time.Time),
		executionLog:  make([]PlaybookExecution, 0, maxExecutionLog),
		actionReg:     actionReg,
	}
}

// Register adds or replaces a playbook.
func (r *InMemoryPlaybookRegistry) Register(playbook Playbook) error {
	if playbook.ID == "" {
		return fmt.Errorf("playbook ID must not be empty")
	}
	if playbook.Trigger == "" {
		return fmt.Errorf("playbook trigger must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p := playbook
	r.playbooks[playbook.ID] = &p
	return nil
}

// Unregister removes a playbook by ID.
func (r *InMemoryPlaybookRegistry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.playbooks[id]; !ok {
		return fmt.Errorf("playbook %q not found", id)
	}
	delete(r.playbooks, id)
	return nil
}

// List returns all registered playbooks.
func (r *InMemoryPlaybookRegistry) List() []Playbook {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Playbook, 0, len(r.playbooks))
	for _, p := range r.playbooks {
		out = append(out, *p)
	}
	return out
}

// entityKeyFromEvent derives a cooldown entity key from the event.
func entityKeyFromEvent(event SecurityEvent) string {
	if event.UserID != "" {
		return event.UserID
	}
	if event.SessionID != "" {
		return event.SessionID
	}
	return event.ClientIP
}

// sevRank returns the numeric rank for a severity string.
func sevRank(sev string) int {
	if r, ok := severityRank[sev]; ok {
		return r
	}
	return 0
}

// Execute finds all playbooks matching the event trigger and executes them.
func (r *InMemoryPlaybookRegistry) Execute(ctx context.Context, event SecurityEvent, store StateStore) (*PlaybookExecution, error) {
	r.mu.RLock()
	var matching []*Playbook
	for _, p := range r.playbooks {
		if p.Enabled && p.Trigger == event.Type {
			if p.Severity != "" && sevRank(event.Severity) < sevRank(p.Severity) {
				continue
			}
			matching = append(matching, p)
		}
	}
	r.mu.RUnlock()

	if len(matching) == 0 {
		return nil, nil
	}

	entityKey := entityKeyFromEvent(event)
	var combined PlaybookExecution
	combined.TriggerEvent = event
	combined.StartedAt = time.Now()

	for _, p := range matching {
		cooldownKey := p.ID + ":" + entityKey

		r.mu.RLock()
		lastExec, hasCooldown := r.lastExecution[cooldownKey]
		r.mu.RUnlock()

		if hasCooldown && p.Cooldown > 0 && time.Since(lastExec) < p.Cooldown {
			continue
		}

		combined.PlaybookID = p.ID

		for i, step := range p.Steps {
			select {
			case <-ctx.Done():
				combined.CompletedAt = time.Now()
				r.recordExecution(combined)
				return &combined, ctx.Err()
			default:
			}

			stepStart := time.Now()
			result := StepResult{
				StepIndex:  i,
				ActionType: step.ActionType,
			}

			err := r.executeStep(ctx, step, event, store)
			result.Duration = time.Since(stepStart)
			if err != nil {
				result.Success = false
				result.Error = err.Error()
				combined.StepsFailed++
			} else {
				result.Success = true
			}

			combined.StepsExecuted++
			combined.Results = append(combined.Results, result)
		}

		r.mu.Lock()
		r.lastExecution[cooldownKey] = time.Now()
		r.mu.Unlock()
	}

	combined.CompletedAt = time.Now()
	r.recordExecution(combined)
	return &combined, nil
}

// executeStep runs a single playbook step by building an Action and dispatching it.
// Playbook steps execute outside of an HTTP request context, so built-in handlers
// that require fiber.Ctx are handled via the StateStore directly.
func (r *InMemoryPlaybookRegistry) executeStep(ctx context.Context, step PlaybookStep, event SecurityEvent, store StateStore) error {
	meta := ActionMeta{
		ClientIP: event.ClientIP,
		Endpoint: event.Path,
		UserID:   event.UserID,
	}

	// Handle playbook-specific action types that don't need fiber.Ctx
	switch step.ActionType {
	case "temp_block", "temporary_ban":
		dur := "15m"
		if d, ok := step.Params["duration"].(string); ok {
			dur = d
		}
		duration, err := time.ParseDuration(dur)
		if err != nil {
			duration = 15 * time.Minute
		}
		if store != nil && meta.ClientIP != "" {
			return store.SetBan(meta.ClientIP, &BanInfo{
				Until:      time.Now().Add(duration),
				Permanent:  false,
				Reason:     fmt.Sprintf("playbook:%s", event.Type),
				StatusCode: 403,
			})
		}
		return nil

	case "permanent_ban":
		if store != nil && meta.ClientIP != "" {
			return store.SetBan(meta.ClientIP, &BanInfo{
				Permanent:  true,
				Reason:     fmt.Sprintf("playbook:%s", event.Type),
				StatusCode: 403,
			})
		}
		return nil

	case "lock_account":
		if store != nil && meta.UserID != "" {
			return store.SetAccountLock(meta.UserID, &AccountLockState{
				AccountID:   meta.UserID,
				Locked:      true,
				LockedAt:    time.Now(),
				LockedUntil: time.Now().Add(1 * time.Hour),
				UnlockAt:    time.Now().Add(1 * time.Hour),
				Reason:      fmt.Sprintf("playbook:%s", event.Type),
			})
		}
		return nil

	case "revoke_token":
		if store != nil && event.SessionID != "" {
			return store.RevokeToken(event.SessionID, time.Now().Add(24*time.Hour))
		}
		return nil

	case "lock_session":
		if store != nil && event.SessionID != "" {
			return store.DeleteSessionState(event.SessionID)
		}
		return nil

	case "challenge", "deny", "notify":
		// These are informational in playbook context (no HTTP response to send).
		// The event is already emitted; SOC notification would go through NotificationRegistry.
		return nil
	}

	// Fall back to action registry for custom handlers (only if they can handle nil fiber.Ctx)
	if r.actionReg != nil {
		handler, ok := r.actionReg.Get(step.ActionType)
		if ok && handler != nil {
			// Custom handlers must be nil-safe for fiber.Ctx when called from playbooks
			return handler.Handle(ctx, nil, Action{Type: step.ActionType}, meta, store, nil, "playbook:"+event.Type)
		}
	}

	return nil
}

// recordExecution appends an execution to the ring buffer log.
func (r *InMemoryPlaybookRegistry) recordExecution(exec PlaybookExecution) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.executionLog) >= maxExecutionLog {
		r.executionLog = r.executionLog[1:]
	}
	r.executionLog = append(r.executionLog, exec)
}

// DefaultPlaybooks returns the built-in playbooks.
func DefaultPlaybooks() []Playbook {
	return []Playbook{
		{
			ID:       "credential_stuffing_success",
			Name:     "Credential Stuffing Success Response",
			Trigger:  "login_success_suspicious",
			Severity: "high",
			Enabled:  true,
			Cooldown: 15 * time.Minute,
			Steps: []PlaybookStep{
				{ActionType: "temp_block", Params: map[string]any{"duration": "15m"}, Description: "Temporarily block the source IP for 15 minutes"},
				{ActionType: "lock_account", Description: "Lock the compromised account"},
				{ActionType: "notify", Params: map[string]any{"channel": "security"}, Description: "Notify the security team"},
			},
		},
		{
			ID:       "brute_force_detected",
			Name:     "Brute Force Detection Response",
			Trigger:  "brute_force",
			Severity: "medium",
			Enabled:  true,
			Cooldown: 30 * time.Minute,
			Steps: []PlaybookStep{
				{ActionType: "temp_block", Params: map[string]any{"duration": "30m"}, Description: "Temporarily block the source IP for 30 minutes"},
				{ActionType: "notify", Params: map[string]any{"channel": "security"}, Description: "Notify the security team"},
			},
		},
		{
			ID:       "sqli_blocked",
			Name:     "SQL Injection Blocked Response",
			Trigger:  "sqli_attempt",
			Severity: "high",
			Enabled:  true,
			Cooldown: 1 * time.Hour,
			Steps: []PlaybookStep{
				{ActionType: "temp_block", Params: map[string]any{"duration": "1h"}, Description: "Temporarily block the source IP for 1 hour"},
				{ActionType: "notify", Params: map[string]any{"channel": "security"}, Description: "Notify the security team"},
			},
		},
		{
			ID:       "token_replay",
			Name:     "Token Replay Attack Response",
			Trigger:  "token_replay",
			Severity: "high",
			Enabled:  true,
			Cooldown: 10 * time.Minute,
			Steps: []PlaybookStep{
				{ActionType: "revoke_token", Description: "Revoke the replayed token"},
				{ActionType: "lock_session", Description: "Lock the associated session"},
				{ActionType: "notify", Params: map[string]any{"channel": "security"}, Description: "Notify the security team"},
			},
		},
		{
			ID:       "privilege_escalation",
			Name:     "Privilege Escalation Response",
			Trigger:  "privilege_escalation",
			Severity: "critical",
			Enabled:  true,
			Cooldown: 5 * time.Minute,
			Steps: []PlaybookStep{
				{ActionType: "deny", Description: "Deny the request immediately"},
				{ActionType: "lock_account", Description: "Lock the offending account"},
				{ActionType: "notify", Params: map[string]any{"channel": "security"}, Description: "Notify the security team"},
			},
		},
		{
			ID:       "anomalous_export",
			Name:     "Anomalous Data Export Response",
			Trigger:  "anomalous_export",
			Severity: "medium",
			Enabled:  true,
			Cooldown: 30 * time.Minute,
			Steps: []PlaybookStep{
				{ActionType: "challenge", Description: "Challenge the user to verify identity"},
				{ActionType: "notify", Params: map[string]any{"channel": "security"}, Description: "Notify the security team"},
			},
		},
	}
}
