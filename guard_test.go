package tcpguard_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/tcpguard"
)

func TestGuardEvaluateBlocksCriticalRuleInEnforceMode(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "after-hours-admin-access",
			Status:    tcpguard.RuleActive,
			Priority:  100,
			Triggers:  []string{"request.received"},
			Scope:     tcpguard.Scope{Roles: []string{"admin"}, Paths: []string{"/admin/*"}},
			Condition: `business.outside_hours == true`,
			Risk: tcpguard.RiskSpec{
				Base: 80,
				Max:  100,
				Adders: []tcpguard.RiskAdder{
					{Value: 15, Condition: `request.method == "POST"`},
				},
			},
			Severity: []tcpguard.SeverityRule{
				{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`},
			},
			Actions: map[tcpguard.Severity][]tcpguard.ActionRef{
				tcpguard.SeverityCritical: {{ID: "block"}, {ID: "create_incident"}},
			},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_1", Path: "/admin/users", Method: http.MethodPost},
		Identity: tcpguard.IdentityContext{ID: "u1", Role: "admin"},
		Business: tcpguard.BusinessContext{OutsideHours: true},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("effect=%s want block", decision.Effect)
	}
	if decision.Risk.Score != 95 {
		t.Fatalf("risk=%v want 95", decision.Risk.Score)
	}
	if len(decision.Incidents) != 1 {
		t.Fatalf("incidents=%d want 1", len(decision.Incidents))
	}
	for _, want := range []string{"Blocked POST /admin/users", "after-hours-admin-access", "outside business hours"} {
		if !strings.Contains(decision.Explanation, want) {
			t.Fatalf("explanation %q missing %q", decision.Explanation, want)
		}
	}
}

func TestBundleFileIntelDerivedTriggerAndCooldown(t *testing.T) {
	dir := t.TempDir()
	intelPath := filepath.Join(dir, "bad_ips.txt")
	if err := os.WriteFile(intelPath, []byte("203.0.113.*\n"), 0o600); err != nil {
		t.Fatalf("write intel: %v", err)
	}
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithBundle(tcpguard.Bundle{
			BaseDir: dir,
			IntelFeeds: []tcpguard.IntelDefinition{{
				ID:     "bad-ip-feed",
				Type:   "file",
				Path:   "bad_ips.txt",
				Match:  "network.ip",
				Fields: map[string]any{"network.reputation": float64(95)},
			}},
			DerivedEvents: []tcpguard.DerivedTrigger{{
				ID:        "threat.bad_ip",
				Source:    "request.received",
				Condition: "network.reputation >= 90",
				Emit:      "threat.bad_ip",
			}},
			Rules: []tcpguard.Rule{{
				ID:       "bad-ip-block",
				Status:   tcpguard.RuleActive,
				Triggers: []string{"threat.bad_ip"},
				Risk:     tcpguard.RiskSpec{Base: 95, Max: 100},
				Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: "risk.score >= 90"}},
				Cooldown: tcpguard.Cooldown{Key: "network.ip", Duration: time.Minute},
				Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
			}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_1", Path: "/api", Method: http.MethodGet},
		Network:  tcpguard.NetworkContext{IP: "203.0.113.10"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("effect=%s want block", decision.Effect)
	}
	again := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if len(again.MatchedRules) != 0 {
		t.Fatalf("cooldown matched rules=%v want none", again.MatchedRules)
	}
}

func TestWebhookActionRendersRequestPlaceholders(t *testing.T) {
	var gotHeader string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Tenant")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithAction(tcpguard.ActionDefinition{
			ID:              "notify_fraud_team",
			Type:            "webhook",
			AllowPrivateURL: true,
			Request: tcpguard.ActionRequest{
				Endpoint: server.URL + "/incidents/{{request.id}}",
				Method:   http.MethodPost,
				Headers:  map[string]string{"X-Tenant": "{{tenant.id}}"},
				Body: map[string]any{
					"request":  tcpguard.Placeholder("request.id"),
					"risk":     tcpguard.Placeholder("risk.score"),
					"severity": tcpguard.Placeholder("severity"),
				},
				Include: map[string]string{"user_id": "user.id"},
				Fields:  map[string]any{"source": "tcpguard"},
			},
		}),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "notify-rule",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Condition: `wildcard_match(request.path, "/admin/*")`,
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity: []tcpguard.SeverityRule{
				{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`},
			},
			Actions: map[tcpguard.Severity][]tcpguard.ActionRef{
				tcpguard.SeverityCritical: {{ID: "notify_fraud_team"}},
			},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_42", Path: "/admin/users", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user_1"},
		Tenant:   tcpguard.TenantContext{ID: "tenant_1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if len(decision.Actions) != 1 || decision.Actions[0].Status != "ok" {
		t.Fatalf("actions=%v", decision.Actions)
	}
	if gotHeader != "tenant_1" {
		t.Fatalf("X-Tenant=%q want tenant_1", gotHeader)
	}
	if gotBody["request"] != "req_42" || gotBody["user_id"] != "user_1" || gotBody["source"] != "tcpguard" || gotBody["risk"].(float64) != 95 {
		t.Fatalf("body=%v", gotBody)
	}
}

func TestWebhookActionRendersEnvContextAndSessionRefs(t *testing.T) {
	t.Setenv("SOC_TOKEN", "secret-token")
	var gotAuth string
	var gotSession string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSession = r.Header.Get("X-Session")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithAction(tcpguard.ActionDefinition{
			ID:              "notify",
			Type:            "webhook",
			AllowPrivateURL: true,
			Request: tcpguard.ActionRequest{
				Endpoint: server.URL + "/{{context(\"request.id\")}}",
				Method:   http.MethodPost,
				Headers: map[string]string{
					"Authorization": "Bearer {{env.SOC_TOKEN}}",
					"X-Session":     "{{session.id}}",
				},
				Body: map[string]any{
					"request": tcpguard.ContextRef("request.id"),
					"session": tcpguard.SessionRef("id"),
					"token":   tcpguard.EnvRef("SOC_TOKEN"),
				},
			},
		}),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "notify-rule",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Condition: `session("id") == "sess_1" and env("SOC_TOKEN") == "secret-token"`,
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "notify"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_env", Path: "/admin/users", Method: http.MethodGet},
		Session:  tcpguard.SessionContext{ID: "sess_1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if len(decision.Actions) != 1 || decision.Actions[0].Status != "ok" {
		t.Fatalf("actions=%v", decision.Actions)
	}
	if gotAuth != "Bearer secret-token" || gotSession != "sess_1" {
		t.Fatalf("auth=%q session=%q", gotAuth, gotSession)
	}
	if gotBody["request"] != "req_env" || gotBody["session"] != "sess_1" || gotBody["token"] != "secret-token" {
		t.Fatalf("body=%v", gotBody)
	}
}

func TestSequenceTriggerMatchesOrderedEvents(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:     "suspicious-export-after-risky-login",
			Status: tcpguard.RuleActive,
			Sequence: &tcpguard.SequenceTrigger{Within: time.Minute, Steps: []tcpguard.SequenceStep{
				{Event: "auth.login_failed", Count: 2},
				{Event: "auth.login_success"},
				{Event: "business.export"},
			}},
			Condition: `business.action == "report.export"`,
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_seq", Path: "/reports/export", Method: http.MethodPost},
		Identity: tcpguard.IdentityContext{ID: "user_seq"},
		Business: tcpguard.BusinessContext{Action: "report.export"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	for _, eventType := range []string{"auth.login_failed", "auth.login_failed", "auth.login_success"} {
		decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: eventType}, sec)
		if len(decision.MatchedRules) != 0 {
			t.Fatalf("event %s matched early: %v", eventType, decision.MatchedRules)
		}
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "business.export"}, sec)
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("effect=%s want block", decision.Effect)
	}
}

func TestFiberV3MiddlewareEnforcesBlock(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{
			DisableGeoIP: true,
			IdentityExtractor: func(_ *http.Request, sec *tcpguard.Context) {
				sec.Identity.Role = "admin"
			},
			BusinessExtractor: func(_ *http.Request, sec *tcpguard.Context) {
				sec.Business.OutsideHours = true
			},
		}),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "admin-block",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Scope:     tcpguard.Scope{Roles: []string{"admin"}, Paths: []string{"/admin/*"}},
			Condition: `business.outside_hours == true`,
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity: []tcpguard.SeverityRule{
				{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`},
			},
			Actions: map[tcpguard.Severity][]tcpguard.ActionRef{
				tcpguard.SeverityCritical: {{ID: "block"}},
			},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	app := fiber.New()
	app.Use(guard.Middleware())
	app.Get("/admin/users", func(c fiber.Ctx) error { return c.SendString("ok") })
	req, _ := http.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("User-Agent", "test")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test returned error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestHTTPMiddlewareCustomResponseAndMetrics(t *testing.T) {
	metrics := tcpguard.NewMemoryMetrics()
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithMetrics(metrics),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{DisableGeoIP: true}),
		tcpguard.WithResponseRenderer(func(sec *tcpguard.Context, decision tcpguard.Decision) tcpguard.DecisionResponse {
			return tcpguard.DecisionResponse{
				Status: http.StatusTeapot,
				Headers: map[string]string{
					"Content-Type":    "application/json",
					"X-Custom-Reason": string(decision.Effect),
				},
				Body: map[string]any{"trace": sec.Request.ID, "effect": decision.Effect},
			}
		}),
		tcpguard.WithRule(tcpguard.Rule{
			ID:       "block-http",
			Status:   tcpguard.RuleActive,
			Triggers: []string{"request.received"},
			Scope:    tcpguard.Scope{Paths: []string{"/blocked"}},
			Risk:     tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: "risk.score >= 90"}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	handler := guard.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/blocked", nil)
	req.Header.Set("X-Request-ID", "req-custom-response")
	req.Header.Set("User-Agent", "demo")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusTeapot, rec.Body.String())
	}
	if rec.Header().Get("X-Custom-Reason") != string(tcpguard.DecisionBlock) {
		t.Fatalf("custom header=%q", rec.Header().Get("X-Custom-Reason"))
	}
	snapshot := metrics.Snapshot()
	if snapshot.Decisions[tcpguard.DecisionBlock] != 1 {
		t.Fatalf("block decisions=%d want 1", snapshot.Decisions[tcpguard.DecisionBlock])
	}
	if snapshot.Actions["block"] != 1 {
		t.Fatalf("block actions=%d want 1", snapshot.Actions["block"])
	}
	if snapshot.Detectors["header-anomaly"] != 1 {
		t.Fatalf("header detector count=%d want 1", snapshot.Detectors["header-anomaly"])
	}
}

func TestHTTPContextBuilderGeoIPCountry(t *testing.T) {
	builder := tcpguard.HTTPContextBuilder{TrustedProxyHeaders: true}
	req, _ := http.NewRequest(http.MethodGet, "/geo", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "27.34.68.218")
	sec, err := builder.BuildHTTP(context.Background(), req)
	if err != nil {
		t.Fatalf("BuildHTTP returned error: %v", err)
	}
	if sec.Network.Country != "NP" || sec.Network.CountryCode != "NP" || !sec.Network.GeoFound {
		t.Fatalf("network=%#v", sec.Network)
	}
}

func TestSafetyRejectsUnapprovedDestructiveAction(t *testing.T) {
	_, err := tcpguard.New(
		tcpguard.WithSafety(tcpguard.PolicySafety{RequireApprovalFor: []string{"block"}}),
		tcpguard.WithRule(tcpguard.Rule{
			ID:       "unsafe-block",
			Status:   tcpguard.RuleActive,
			Triggers: []string{"request.received"},
			Risk:     tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err == nil {
		t.Fatal("expected safety validation error")
	}
}

func TestDynamicRoutePatternMatchesAndExtractsParams(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "dynamic-route",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Scope:     tcpguard.Scope{Paths: []string{"/api/users/:id/order/:order_id"}},
			Condition: `request.params.id == "u1" and request.params.order_id == "o9"`,
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_route", Path: "/api/users/u1/order/o9", Method: http.MethodGet},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("effect=%s want block params=%v", decision.Effect, sec.Request.Params)
	}
	if sec.Request.Params["id"] != "u1" || sec.Request.Params["order_id"] != "o9" {
		t.Fatalf("params=%v", sec.Request.Params)
	}
}

func TestApprovalPipelineApproveAndReject(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	guard, err := tcpguard.New(
		tcpguard.WithStore(store),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:       "needs-approval",
			Status:   tcpguard.RuleActive,
			Triggers: []string{"request.received"},
			Approval: tcpguard.Approval{Required: true, Approvers: []string{"alice"}},
			Risk:     tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}, {ID: "create_incident"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_approval", Path: "/admin", Method: http.MethodPost},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	first := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if first.Effect != tcpguard.DecisionChallenge || first.Allowed || len(first.Actions) != 0 || len(first.Approvals) != 1 {
		t.Fatalf("first decision=%#v", first)
	}
	if first.Approvals[0].Status != tcpguard.ApprovalPending {
		t.Fatalf("approval=%#v", first.Approvals[0])
	}
	if _, err := guard.Approve(context.Background(), first.Approvals[0].ID, "mallory", "nope"); err == nil {
		t.Fatal("expected unauthorized approver error")
	}
	approved, err := guard.Approve(context.Background(), first.Approvals[0].ID, "alice", "confirmed incident")
	if err != nil {
		t.Fatalf("Approve returned error: %v", err)
	}
	if approved.Status != tcpguard.ApprovalApproved || approved.Reason != "confirmed incident" {
		t.Fatalf("approved=%#v", approved)
	}
	second := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if second.Effect != tcpguard.DecisionBlock || len(second.Actions) != 2 {
		t.Fatalf("second decision=%#v", second)
	}

	rejectSec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_reject", Path: "/admin", Method: http.MethodPost},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	pending := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, rejectSec)
	if len(pending.Approvals) != 1 {
		t.Fatalf("pending reject decision=%#v", pending)
	}
	rejected, err := guard.Reject(context.Background(), pending.Approvals[0].ID, "alice", "false positive")
	if err != nil {
		t.Fatalf("Reject returned error: %v", err)
	}
	if rejected.Status != tcpguard.ApprovalRejected || rejected.Reason != "false positive" {
		t.Fatalf("rejected=%#v", rejected)
	}
	afterReject := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, rejectSec)
	if afterReject.Effect != tcpguard.DecisionChallenge || afterReject.Allowed || len(afterReject.Actions) != 0 || afterReject.Approvals[0].Status != tcpguard.ApprovalRejected {
		t.Fatalf("after reject=%#v", afterReject)
	}
}

func TestDSLDetectorAndThreatModelDecorateFindings(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithBundle(tcpguard.Bundle{
			Detectors: []tcpguard.DetectorDefinition{{
				ID:   "sensitive-detector",
				Type: "dsl",
				Findings: []tcpguard.DetectorFindingDefinition{{
					ID:        "sensitive_endpoint_access",
					Condition: `request.path matches "/admin/*"`,
					Risk:      80,
					Message:   "admin endpoint",
				}},
				Outputs: map[string]any{"endpoint.sensitive": true},
			}},
			ThreatModels: []tcpguard.ThreatModelDefinition{{
				ID: "stride-default",
				Categories: map[string][]string{
					"information_disclosure": {"sensitive_endpoint_access"},
				},
			}},
			Rules: []tcpguard.Rule{{
				ID:        "detector-rule",
				Status:    tcpguard.RuleActive,
				Triggers:  []string{"request.received"},
				Condition: `endpoint.sensitive == true`,
				Risk:      tcpguard.RiskSpec{Base: 90, Max: 100},
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
		Request:  tcpguard.RequestContext{ID: "req_detector", Path: "/admin/users", Method: http.MethodGet},
		Security: map[string]any{},
		Rate:     map[string]any{},
	})
	if decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("effect=%s want block", decision.Effect)
	}
	if len(decision.Findings) == 0 || len(decision.Findings[0].STRIDE) == 0 {
		t.Fatalf("finding missing threat mapping: %#v", decision.Findings)
	}
}

func TestEntityProfilesArePersisted(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	guard, err := tcpguard.New(
		tcpguard.WithStore(store),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:       "profile-rule",
			Status:   tcpguard.RuleActive,
			Triggers: []string{"request.received"},
			Risk:     tcpguard.RiskSpec{Base: 80, Max: 100, Decay: time.Hour},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityHigh, Condition: `risk.score >= 75`}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityHigh: {{ID: "mfa_challenge"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_profile", Path: "/api", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user_profile"},
		Tenant:   tcpguard.TenantContext{ID: "tenant_profile"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	})
	if len(decision.Profiles) == 0 {
		t.Fatal("expected persisted profiles on decision")
	}
	if _, found, err := store.Get(context.Background(), "profile:user:user_profile"); err != nil || !found {
		t.Fatalf("profile found=%v err=%v", found, err)
	}
}

func TestAuditEnvelopeChainAndRequestFingerprint(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	guard, err := tcpguard.New(
		tcpguard.WithStore(store),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:       "audit-rule",
			Status:   tcpguard.RuleActive,
			Triggers: []string{"request.received"},
			Risk:     tcpguard.RiskSpec{Base: 80, Max: 100},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityHigh, Condition: `risk.score >= 75`}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityHigh: {{ID: "mfa_challenge"}}},
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req_audit", Path: "/api", Method: http.MethodGet},
		Identity: tcpguard.IdentityContext{ID: "user_audit"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if decision.AuditEnvelope == nil {
		t.Fatal("expected audit envelope")
	}
	if decision.Audit.RequestFingerprint == "" || len(decision.Audit.ActionResults) != 1 {
		t.Fatalf("audit=%#v", decision.Audit)
	}
	envelopes, err := store.ListAuditEnvelopes(context.Background())
	if err != nil {
		t.Fatalf("ListAuditEnvelopes returned error: %v", err)
	}
	if err := tcpguard.VerifyAuditChain(envelopes); err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
}

func TestReloadableGuardKeepsLastKnownGoodOnInvalidPublish(t *testing.T) {
	good := tcpguard.Bundle{
		Rules: []tcpguard.Rule{{
			ID:       "good",
			Status:   tcpguard.RuleActive,
			Triggers: []string{"request.received"},
			Risk:     tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}},
	}
	loader := func(context.Context, string) (tcpguard.Bundle, error) { return good, nil }
	runtime, err := tcpguard.NewReloadableGuard(context.Background(), "memory", loader, tcpguard.WithMode(tcpguard.Enforce))
	if err != nil {
		t.Fatalf("NewReloadableGuard returned error: %v", err)
	}
	err = runtime.Publish(context.Background(), tcpguard.Bundle{Rules: []tcpguard.Rule{{Status: tcpguard.RuleActive}}}, tcpguard.WithMode(tcpguard.Enforce))
	if err == nil {
		t.Fatal("expected invalid publish to fail")
	}
	if len(runtime.LastKnownGood().Rules) != 1 || runtime.LastKnownGood().Rules[0].ID != "good" {
		t.Fatalf("last known good changed: %#v", runtime.LastKnownGood())
	}
}
