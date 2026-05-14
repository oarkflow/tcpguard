package tcpguard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementServerRejectsWithoutAuthConfig(t *testing.T) {
	g, err := New(WithMode(Enforce))
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	s := ManagementServer{Guard: &ReloadableGuard{guard: g}}
	req := httptest.NewRequest(http.MethodPost, "/simulate", strings.NewReader(`{"event":{"type":"request.received"}}`))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", w.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(w.Body.String(), `"code":"auth_required"`) {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestManagementServerRBACDenyByDefault(t *testing.T) {
	g, err := New(WithMode(Enforce))
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	s := NewManagementServer(&ReloadableGuard{guard: g}, ManagementServerConfig{
		AuthProvider: StaticAPIKeyAuth{
			Keys: map[string]ManagementPrincipal{"k": {Subject: "ops", Roles: []string{"admin"}}},
		},
		Authorizer: RoleBasedAuthorizer{
			RolesByRoute: map[ManagementRoute][]string{
				ManagementRouteReload: {"admin"},
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/simulate", strings.NewReader(`{"event":{"type":"request.received"}}`))
	req.Header.Set("X-API-Key", "k")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), `"code":"rbac_denied"`) {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestManagementServerDefaultBodyLimit(t *testing.T) {
	g, err := New(WithMode(Enforce))
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	s := NewManagementServer(&ReloadableGuard{guard: g}, ManagementServerConfig{
		AuthProvider: StaticAPIKeyAuth{
			Keys: map[string]ManagementPrincipal{"k": {Subject: "ops", Roles: []string{"admin"}}},
		},
		Authorizer: RoleBasedAuthorizer{
			RolesByRoute: map[ManagementRoute][]string{
				ManagementRouteSimulate: {"admin"},
			},
		},
	})
	large := bytes.Repeat([]byte("a"), (1<<20)+1024)
	body := `{"event":{"type":"request.received"},"context":{"extra":{"blob":"` + string(large) + `"}}}`
	req := httptest.NewRequest(http.MethodPost, "/simulate", strings.NewReader(body))
	req.Header.Set("X-API-Key", "k")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestValidateStatusRangeDefs(t *testing.T) {
	if err := validateStatusRangeDefs([]string{"2xx", "500-599", "409"}); err != nil {
		t.Fatalf("expected valid status definitions, got %v", err)
	}
	if err := validateStatusRangeDefs([]string{"70x"}); err == nil {
		t.Fatal("expected invalid status definitions to error")
	}
}

func TestNewRejectsInvalidActionStatusCodes(t *testing.T) {
	_, err := New(
		WithMode(Enforce),
		WithAction(ActionDefinition{
			ID:              "notify",
			Type:            "webhook",
			AllowPrivateURL: true,
			Request:         ActionRequest{Endpoint: "http://127.0.0.1:9999"},
			SuccessCodes:    []string{"70x"},
		}),
		WithRule(Rule{
			ID:       "r",
			Status:   RuleActive,
			Triggers: []string{"request.received"},
			Risk:     RiskSpec{Base: 90, Max: 100},
			Severity: []SeverityRule{{Severity: SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:  map[Severity][]ActionRef{SeverityCritical: {{ID: "notify"}}},
		}),
	)
	if err == nil {
		t.Fatal("expected error for invalid success_codes")
	}
}

func TestResolvedRetentionDefaults(t *testing.T) {
	s := RedisStore{Retention: RetentionPolicy{AuditTTL: 5}}
	r := s.resolvedRetention()
	if r.IncidentsTTL <= 0 || r.AuditTTL != 5 || r.MaxApprovals <= 0 {
		t.Fatalf("resolved retention not merged correctly: %#v", r)
	}
}

func TestHTTPDataSourceBlocksPrivateURLByDefault(t *testing.T) {
	_, err := dataSourceFromDefinition(DataSourceDefinition{
		ID:     "risk",
		Type:   "http",
		URL:    "http://127.0.0.1:18181/risk",
		Method: http.MethodPost,
	}, nil)
	if err == nil {
		t.Fatal("expected private URL to be rejected by default")
	}
}

func TestHTTPDataSourceAllowsPrivateURLWhenEnabled(t *testing.T) {
	source, err := dataSourceFromDefinition(DataSourceDefinition{
		ID:              "risk",
		Type:            "http",
		URL:             "http://127.0.0.1:18181/risk",
		Method:          http.MethodPost,
		AllowPrivateURL: true,
	}, nil)
	if err != nil {
		t.Fatalf("expected private URL allowed when configured, got %v", err)
	}
	if source == nil {
		t.Fatal("expected datasource")
	}
}

func TestDecodeManagementJSONSingleObject(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/simulate", strings.NewReader(`{"id":"1"} {"id":"2"}`))
	var payload map[string]any
	err := decodeManagementJSON(req, &payload)
	if err == nil {
		t.Fatal("expected error for multiple JSON objects")
	}
}

func TestAuthErrorShape(t *testing.T) {
	g, err := New(WithMode(Enforce))
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	s := NewManagementServer(&ReloadableGuard{guard: g}, ManagementServerConfig{
		AuthProvider: StaticAPIKeyAuth{Keys: map[string]ManagementPrincipal{"k": {Subject: "ops", Roles: []string{"admin"}}}},
		Authorizer: RoleBasedAuthorizer{RolesByRoute: map[ManagementRoute][]string{
			ManagementRouteSimulate: {"admin"},
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/simulate", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", w.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(w.Body.String(), `"code":"auth_failed"`) {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestContextSessionEnvDefaultsAtRuntime(t *testing.T) {
	t.Setenv("NON_EXISTING_ENV", "")
	sec := &Context{
		Request:  RequestContext{ID: "r1"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	if got := renderStructuredValue(EnvRef(encodeRefArgs([]string{"NON_EXISTING_ENV", "fallback"})), sec, Decision{}); got != "fallback" {
		t.Fatalf("env default not applied: %v", got)
	}
	if got := renderStructuredValue(ContextRef(encodeRefArgs([]string{"user.unknown", "anon"})), sec, Decision{}); got != "anon" {
		t.Fatalf("context default not applied: %v", got)
	}
	if got := renderStructuredValue(SessionRef(encodeRefArgs([]string{"unknown", "anon-sess"})), sec, Decision{}); got != "anon-sess" {
		t.Fatalf("session default not applied: %v", got)
	}
}

func TestNewRejectsInvalidRefArity(t *testing.T) {
	_, err := New(
		WithMode(Enforce),
		WithAction(ActionDefinition{
			ID:   "notify",
			Type: "event_bus",
			Request: ActionRequest{
				Body: map[string]any{
					"bad": EnvRef(encodeRefArgs([]string{"A", "B", "C"})),
				},
			},
		}),
		WithRule(Rule{
			ID:       "r",
			Status:   RuleActive,
			Triggers: []string{"request.received"},
			Risk:     RiskSpec{Base: 90, Max: 100},
			Severity: []SeverityRule{{Severity: SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:  map[Severity][]ActionRef{SeverityCritical: {{ID: "notify"}}},
		}),
	)
	if err == nil {
		t.Fatal("expected invalid ref arity to fail")
	}
}
