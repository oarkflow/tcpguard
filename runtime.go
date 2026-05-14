package tcpguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

type BundleLoader func(context.Context, string) (Bundle, error)

type SimulationRequest struct {
	Event   Event    `json:"event"`
	Context *Context `json:"context"`
}

type SimulationResult struct {
	Decision Decision `json:"decision"`
}

type SimulationDiff struct {
	EffectChanged   bool     `json:"effect_changed"`
	RiskDelta       float64  `json:"risk_delta"`
	SeverityChanged bool     `json:"severity_changed"`
	AddedRules      []string `json:"added_rules,omitempty"`
	RemovedRules    []string `json:"removed_rules,omitempty"`
}

func Simulate(ctx context.Context, bundle Bundle, req SimulationRequest) (SimulationResult, error) {
	guard, err := New(WithBundle(bundle), WithMode(DryRun))
	if err != nil {
		return SimulationResult{}, err
	}
	return SimulationResult{Decision: guard.Evaluate(ctx, req.Event, req.Context)}, nil
}

func DiffSimulations(ctx context.Context, before, after Bundle, req SimulationRequest) (SimulationDiff, error) {
	left, err := Simulate(ctx, before, req)
	if err != nil {
		return SimulationDiff{}, err
	}
	right, err := Simulate(ctx, after, req)
	if err != nil {
		return SimulationDiff{}, err
	}
	return diffDecisions(left.Decision, right.Decision), nil
}

type ReloadableGuard struct {
	mu       sync.RWMutex
	guard    *Guard
	lastGood Bundle
	loader   BundleLoader
	source   string
}

func NewReloadableGuard(ctx context.Context, source string, loader BundleLoader, opts ...Option) (*ReloadableGuard, error) {
	bundle, err := loader(ctx, source)
	if err != nil {
		return nil, err
	}
	options := append([]Option{WithBundle(bundle)}, opts...)
	guard, err := New(options...)
	if err != nil {
		return nil, err
	}
	return &ReloadableGuard{guard: guard, lastGood: bundle, loader: loader, source: source}, nil
}

func (r *ReloadableGuard) Guard() *Guard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.guard
}

func (r *ReloadableGuard) Middleware() http.Handler {
	return r.Guard().HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func (r *ReloadableGuard) Evaluate(ctx context.Context, event Event, sec *Context) Decision {
	return r.Guard().Evaluate(ctx, event, sec)
}

func (r *ReloadableGuard) Reload(ctx context.Context, opts ...Option) error {
	started := time.Now()
	bundle, err := r.loader(ctx, r.source)
	if err != nil {
		r.Guard().recordReload(ctx, false, time.Since(started))
		return err
	}
	err = r.Publish(ctx, bundle, opts...)
	r.Guard().recordReload(ctx, err == nil, time.Since(started))
	return err
}

func (r *ReloadableGuard) Publish(_ context.Context, bundle Bundle, opts ...Option) error {
	options := append([]Option{WithBundle(bundle)}, opts...)
	guard, err := New(options...)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.guard = guard
	r.lastGood = bundle
	r.mu.Unlock()
	return nil
}

func (r *ReloadableGuard) LastKnownGood() Bundle {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastGood
}

type ManagementServer struct {
	Guard  *ReloadableGuard
	Config ManagementServerConfig
}

func (s ManagementServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Guard == nil || s.Guard.Guard() == nil {
		writeManagementError(w, http.StatusServiceUnavailable, "tcpguard is not initialized")
		return
	}
	route, ok := s.authorizeManagementRequest(w, r)
	if !ok {
		return
	}
	if s.Config.MaxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.Config.MaxBodyBytes)
	}
	ctx, cancel := managementContext(r, s.Config)
	defer cancel()
	r = r.WithContext(ctx)
	switch route {
	case ManagementRouteHealth:
		writeManagementJSON(w, http.StatusOK, map[string]any{"ok": true})
	case ManagementRouteReload:
		if err := s.Guard.Reload(r.Context()); err != nil {
			writeManagementError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeManagementJSON(w, http.StatusOK, map[string]any{"reloaded": true})
	case ManagementRouteSimulate:
		var req SimulationRequest
		if err := decodeManagementJSON(r, &req); err != nil {
			writeManagementError(w, http.StatusBadRequest, err.Error())
			return
		}
		decision := s.Guard.Evaluate(r.Context(), req.Event, req.Context)
		writeManagementJSON(w, http.StatusOK, SimulationResult{Decision: decision})
	case ManagementRouteIncidents:
		store := s.Guard.Guard().incidentStore
		if store == nil {
			writeManagementJSON(w, http.StatusOK, paginatedResponse[Incident]{Items: []Incident{}})
			return
		}
		incidents, err := store.ListIncidents(r.Context())
		if err != nil {
			writeManagementError(w, http.StatusInternalServerError, err.Error())
			return
		}
		query := parsePaginationQuery(r, 200)
		writeManagementJSON(w, http.StatusOK, paginateItems(incidents, query, func(v Incident) time.Time { return v.CreatedAt }))
	case ManagementRouteAudit:
		store := s.Guard.Guard().auditStore
		if store == nil {
			writeManagementJSON(w, http.StatusOK, paginatedResponse[AuditEnvelope]{Items: []AuditEnvelope{}})
			return
		}
		envelopes, err := store.ListAuditEnvelopes(r.Context())
		if err != nil {
			writeManagementError(w, http.StatusInternalServerError, err.Error())
			return
		}
		query := parsePaginationQuery(r, 200)
		writeManagementJSON(w, http.StatusOK, paginateItems(envelopes, query, func(v AuditEnvelope) time.Time { return v.Record.At }))
	case ManagementRouteAuditVerify:
		store := s.Guard.Guard().auditStore
		if store == nil {
			writeManagementJSON(w, http.StatusOK, map[string]any{"valid": true, "envelopes": 0})
			return
		}
		envelopes, err := store.ListAuditEnvelopes(r.Context())
		if err != nil {
			writeManagementError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := VerifyAuditChain(envelopes); err != nil {
			writeManagementJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error(), "envelopes": len(envelopes)})
			return
		}
		writeManagementJSON(w, http.StatusOK, map[string]any{"valid": true, "envelopes": len(envelopes)})
	case ManagementRouteExplain:
		var req SimulationRequest
		if err := decodeManagementJSON(r, &req); err != nil {
			writeManagementError(w, http.StatusBadRequest, err.Error())
			return
		}
		decision := s.Guard.Evaluate(r.Context(), req.Event, req.Context)
		writeManagementJSON(w, http.StatusOK, ExplainDecision(decision))
	case ManagementRouteApprovals:
		status := ApprovalStatus(r.URL.Query().Get("status"))
		records, err := s.Guard.Guard().ListApprovals(r.Context(), status)
		if err != nil {
			writeManagementError(w, http.StatusInternalServerError, err.Error())
			return
		}
		query := parsePaginationQuery(r, 200)
		writeManagementJSON(w, http.StatusOK, paginateItems(records, query, func(v ApprovalRecord) time.Time { return v.RequestedAt }))
	case ManagementRouteApprovalsApprove:
		s.decideApproval(w, r, ApprovalApproved)
	case ManagementRouteApprovalsReject:
		s.decideApproval(w, r, ApprovalRejected)
	default:
		writeManagementError(w, http.StatusNotFound, "not found")
	}
}

func ExplainDecision(decision Decision) map[string]any {
	return map[string]any{
		"effect":      decision.Effect,
		"allowed":     decision.Allowed,
		"risk":        decision.Risk,
		"severity":    decision.Severity,
		"matched":     decision.MatchedRules,
		"findings":    decision.Findings,
		"evidence":    decision.Evidence,
		"actions":     decision.Actions,
		"approvals":   decision.Approvals,
		"incidents":   decision.Incidents,
		"explanation": decision.Explanation,
		"audit":       decision.Audit,
		"audit_hash":  auditHashFromDecision(decision),
		"policy":      map[string]any{"version": decision.PolicyVersion, "config_hash": decision.ConfigHash},
	}
}

func auditHashFromDecision(decision Decision) string {
	if decision.AuditEnvelope != nil {
		return decision.AuditEnvelope.ChainHash
	}
	return ""
}

func diffDecisions(left, right Decision) SimulationDiff {
	return SimulationDiff{
		EffectChanged:   left.Effect != right.Effect,
		RiskDelta:       right.Risk.Score - left.Risk.Score,
		SeverityChanged: left.Severity != right.Severity,
		AddedRules:      difference(right.MatchedRules, left.MatchedRules),
		RemovedRules:    difference(left.MatchedRules, right.MatchedRules),
	}
}

func difference(values, existing []string) []string {
	seen := map[string]bool{}
	for _, value := range existing {
		seen[value] = true
	}
	var out []string
	for _, value := range values {
		if !seen[value] {
			out = append(out, value)
		}
	}
	return out
}

func (s ManagementServer) decideApproval(w http.ResponseWriter, r *http.Request, status ApprovalStatus) {
	var req struct {
		ID       string `json:"id"`
		Approver string `json:"approver"`
		Reason   string `json:"reason"`
	}
	if err := decodeManagementJSON(r, &req); err != nil {
		writeManagementError(w, http.StatusBadRequest, err.Error())
		return
	}
	var (
		record ApprovalRecord
		err    error
	)
	if status == ApprovalApproved {
		record, err = s.Guard.Guard().Approve(r.Context(), req.ID, req.Approver, req.Reason)
	} else {
		record, err = s.Guard.Guard().Reject(r.Context(), req.ID, req.Approver, req.Reason)
	}
	if err != nil {
		writeManagementError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeManagementJSON(w, http.StatusOK, record)
}

func decodeManagementJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("management request must contain a single JSON object")
		}
		return err
	}
	return nil
}

func writeManagementJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeManagementError(w http.ResponseWriter, status int, message string) {
	writeManagementJSON(w, status, map[string]any{"error": message})
}
