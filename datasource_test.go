package tcpguard_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oarkflow/condition/tcpguard"
	_ "modernc.org/sqlite"
)

func TestLookupPreloadMemoryDataSourceMapsFacts(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithDataSource(tcpguard.MemoryDataSource{
			SourceID: "risk-cache",
			Values: map[string]any{
				"profile:user:user-1": map[string]any{"score": 91, "tier": "high"},
			},
		}),
		tcpguard.WithBundle(tcpguard.Bundle{
			Lookups: []tcpguard.LookupDefinition{{
				ID:      "user-risk-profile",
				Source:  "risk-cache",
				Mode:    "preload",
				Key:     `concat("profile:user:", user.id)`,
				Outputs: map[string]string{"score": "user.external_risk.score", "tier": "user.external_risk.tier"},
				Fallback: tcpguard.LookupFallback{
					Policy: tcpguard.LookupFallbackDefault,
					Value:  map[string]any{"score": 0, "tier": "unknown"},
				},
			}},
			Rules: []tcpguard.Rule{{
				ID:        "external-risk",
				Status:    tcpguard.RuleActive,
				Triggers:  []string{"request.received"},
				Condition: `user.external_risk.score >= 90`,
				Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
				Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
				Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
			}},
		}),
		tcpguard.WithMode(tcpguard.Enforce),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_lookup", Path: "/profile", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user-1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	})
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestStoreFunctionsAndLookupCache(t *testing.T) {
	source := &countingSource{values: map[string]any{"ban:user:user-1": map[string]any{"locked": true}}}
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithDataSource(source),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "cache-ban",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Condition: `store.exists("cache", concat("ban:user:", user.id)) == true and store.value("cache", concat("ban:user:", user.id)) != ""`,
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
		tcpguard.WithMode(tcpguard.Enforce),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_store_fn", Path: "/profile", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user-1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	})
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("decision=%#v", decision)
	}
	if source.calls != 1 {
		t.Fatalf("lookup calls=%d want 1", source.calls)
	}
}

func TestLookupFallbackChallenge(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithDataSource(errorSource{id: "user-db"}),
		tcpguard.WithBundle(tcpguard.Bundle{
			Lookups: []tcpguard.LookupDefinition{{
				ID:       "user-account-status",
				Source:   "user-db",
				Mode:     "preload",
				Key:      "user.id",
				Fallback: tcpguard.LookupFallback{Policy: tcpguard.LookupFallbackChallenge, Reason: "user database unavailable"},
			}},
		}),
		tcpguard.WithMode(tcpguard.Enforce),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_fallback", Path: "/profile", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user-1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	})
	if decision.Effect != tcpguard.DecisionChallenge || !strings.Contains(decision.Explanation, "user database unavailable") || !strings.Contains(decision.Explanation, "user-account-status") {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestPreloadLookupsRunOnlyForCandidateRules(t *testing.T) {
	sourceA := &namedCountingSource{id: "cache-a", values: map[string]any{"user-1": map[string]any{"score": 95}}}
	sourceB := &namedCountingSource{id: "cache-b", values: map[string]any{"user-1": map[string]any{"score": 95}}}
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithDataSource(sourceA),
		tcpguard.WithDataSource(sourceB),
		tcpguard.WithBundle(tcpguard.Bundle{
			Lookups: []tcpguard.LookupDefinition{
				{ID: "risk-a", Source: "cache-a", Mode: "preload", Key: "user.id", Outputs: map[string]string{"score": "user.risk_a.score"}},
				{ID: "risk-b", Source: "cache-b", Mode: "preload", Key: "user.id", Outputs: map[string]string{"score": "user.risk_b.score"}},
			},
			Rules: []tcpguard.Rule{
				{ID: "rule-a", Status: tcpguard.RuleActive, Triggers: []string{"request.received"}, Scope: tcpguard.Scope{Paths: []string{"/a"}}, Condition: `user.risk_a.score >= 90`, Risk: tcpguard.RiskSpec{Base: 95, Max: 100}},
				{ID: "rule-b", Status: tcpguard.RuleActive, Triggers: []string{"request.received"}, Scope: tcpguard.Scope{Paths: []string{"/b"}}, Condition: `user.risk_b.score >= 90`, Risk: tcpguard.RiskSpec{Base: 95, Max: 100}},
			},
		}),
		tcpguard.WithMode(tcpguard.Enforce),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_lookup_candidates", Path: "/a", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user-1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	})
	if decision.Risk.Score != 95 {
		t.Fatalf("decision=%#v", decision)
	}
	if sourceA.calls != 1 || sourceB.calls != 0 {
		t.Fatalf("lookup calls sourceA=%d sourceB=%d want 1,0", sourceA.calls, sourceB.calls)
	}
}

func TestHTTPAndSQLDataSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"risk": 88, "label": "elevated"})
	}))
	defer server.Close()
	httpSource := tcpguard.HTTPDataSource{Definition: tcpguard.DataSourceDefinition{ID: "risk-api", Type: "http", URL: server.URL, Method: http.MethodPost}}
	httpResult, err := httpSource.Lookup(context.Background(), tcpguard.LookupRequest{Key: "user-1"})
	if err != nil || !httpResult.Found || httpResult.Fields["label"] != "elevated" {
		t.Fatalf("http result=%#v err=%v", httpResult, err)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT, locked BOOLEAN); INSERT INTO users (id, status, locked) VALUES ('user-1', 'suspended', true);`)
	if err != nil {
		t.Fatalf("seed sqlite: %v", err)
	}
	sqlSource := tcpguard.SQLDataSource{SourceID: "user-db", DB: db}
	sqlResult, err := sqlSource.Lookup(context.Background(), tcpguard.LookupRequest{
		Query:  "SELECT status, locked FROM users WHERE id = :user_id",
		Params: map[string]any{"user_id": "user-1"},
	})
	if err != nil || !sqlResult.Found || sqlResult.Fields["status"] != "suspended" || sqlResult.Fields["locked"] != true {
		t.Fatalf("sql result=%#v err=%v", sqlResult, err)
	}
}

type countingSource struct {
	values map[string]any
	calls  int
}

func (s *countingSource) ID() string { return "cache" }
func (s *countingSource) Lookup(_ context.Context, req tcpguard.LookupRequest) (tcpguard.LookupResult, error) {
	s.calls++
	value, found := s.values[req.Key]
	return tcpguard.LookupResult{Found: found, Value: value, Fields: map[string]any{"value": value}}, nil
}

type namedCountingSource struct {
	id     string
	values map[string]any
	calls  int
}

func (s *namedCountingSource) ID() string { return s.id }
func (s *namedCountingSource) Lookup(_ context.Context, req tcpguard.LookupRequest) (tcpguard.LookupResult, error) {
	s.calls++
	value, found := s.values[req.Key]
	if fields, ok := value.(map[string]any); ok {
		return tcpguard.LookupResult{Found: found, Value: value, Fields: fields}, nil
	}
	return tcpguard.LookupResult{Found: found, Value: value, Fields: map[string]any{"value": value}}, nil
}

type errorSource struct{ id string }

func (s errorSource) ID() string { return s.id }
func (s errorSource) Lookup(context.Context, tcpguard.LookupRequest) (tcpguard.LookupResult, error) {
	return tcpguard.LookupResult{}, assertErr("boom")
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
