package tcpguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/oarkflow/authz"
)

const fullAuthzBlockDSL = `
tenant root {
  name "Root Organization"
}
tenant org1 {
  name "Engineering Org"
  parent root
}
tenant team1 {
  name "Backend Team"
  parent org1
}
policy allow-read {
  tenant org1
  effect allow
  actions [read]
  resources [document:*]
  when {
    subject.type == "user"
  }
  priority 10
}
policy deny-sensitive {
  tenant org1
  effect deny
  actions [read write delete]
  resources [document:sensitive:*]
  when {
    subject.attrs.clearance != "high"
  }
  priority 50
}
policy owner-access {
  tenant org1
  effect allow
  actions [read write delete]
  resources [document:*]
  when {
    resource.owner_id == subject.id
  }
  priority 50
}
policy route-admin-api {
  tenant org1
  effect allow
  actions [GET POST PUT DELETE]
  resources [route:*]
  when {
    subject.roles contains any [admin superadmin]
  }
  priority 90
}
role editor {
  tenant org1
  name "Editor"
  permissions [read:document:* write:document:* delete:document:*]
}
role team-lead {
  tenant team1
  name "Team Lead"
  inherits [editor]
  permissions [*:project:*]
}
role route-admin {
  tenant org1
  name "Route Administrator"
  permissions [GET:route:GET:/admin/* POST:route:POST:/admin/*]
}
acl acl-route-public {
  resource route:GET:/public/info
  subject guest
  actions [GET]
  effect allow
}
members {
  user:alice [route-admin]
  user:bob [editor]
  user:dave [team-lead]
}
engine {
  cache_ttl 5000
  attr_ttl 10000
  batch_size 128
  flush_interval 50
  workers 8
}
`

func TestOarkflowAuthzProviderSupportsFullBlockDSL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "full.authz")
	if err := os.WriteFile(path, []byte(fullAuthzBlockDSL), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewOarkflowAuthzProviderFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Engine() == nil {
		t.Fatal("expected configured authz engine")
	}

	tests := []struct {
		name, subject, tenant, action, resource, owner, clearance string
		allowed                                                   bool
	}{
		{name: "membership role", subject: "user:alice", tenant: "org1", action: "GET", resource: "route:GET:/admin/users", allowed: true},
		{name: "role permission", subject: "user:bob", tenant: "org1", action: "write", resource: "document:ordinary:1", allowed: true},
		{name: "deny precedence", subject: "user:bob", tenant: "org1", action: "read", resource: "document:sensitive:1", clearance: "low", allowed: false},
		{name: "owner policy", subject: "user:carol", tenant: "org1", action: "write", resource: "document:42", owner: "user:carol", allowed: true},
		{name: "inherited role", subject: "user:dave", tenant: "team1", action: "read", resource: "document:42", allowed: true},
		{name: "route acl", subject: "guest", tenant: "org1", action: "GET", resource: "route:GET:/public/info", allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := map[string]any{"resource.owner_id": tt.owner}
			if tt.clearance != "" {
				attrs["clearance"] = tt.clearance
			}
			decision, err := provider.Authorize(context.Background(), AuthzRequest{
				Action: tt.action, Resource: tt.resource,
				Subject: map[string]any{"id": tt.subject, "type": "user", "tenant_id": tt.tenant}, Attrs: attrs,
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != tt.allowed {
				t.Fatalf("allowed=%v want %v reason=%q matched_by=%q", decision.Allowed, tt.allowed, decision.Evidence.Reason, decision.Evidence.MatchedBy)
			}
		})
	}
	if err := provider.Engine().CreateRole(context.Background(), &authz.Role{
		ID: "runtime-auditor", TenantID: "org1", Name: "Runtime Auditor",
		Permissions: []authz.Permission{{Action: "read", Resource: "audit:*"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Engine().AssignRoleToUser(context.Background(), "service:auditor", "runtime-auditor"); err != nil {
		t.Fatal(err)
	}
	decision, err := provider.Authorize(context.Background(), AuthzRequest{
		Action: "read", Resource: "audit:events",
		Subject: map[string]any{"id": "service:auditor", "type": "service", "tenant_id": "org1"},
	})
	if err != nil || !decision.Allowed {
		t.Fatalf("runtime AuthZ updates not applied: allowed=%v err=%v", decision.Allowed, err)
	}
}

func TestHTTPAuthzEnforcementUsesConfiguredDSL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.authz")
	data := `tenant org1 {
  name "Org"
}
role admin {
  tenant org1
  name "Admin"
  permissions [GET:route:GET:/admin/*]
}
members {
  user:alice [admin]
}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := New(
		WithMode(Enforce), WithoutDefaultDetectors(),
		WithContextBuilder(HTTPContextBuilder{DisableGeoIP: true, IdentityExtractor: func(r *http.Request, sec *Context) {
			sec.Identity.ID = r.Header.Get("X-Subject-ID")
			sec.Identity.Tenant = r.Header.Get("X-Tenant-ID")
		}}),
		WithAuthzConfig(AuthzConfig{File: path, EnforceHTTP: true, ErrorPolicy: AuthzErrorDeny}),
	)
	if err != nil {
		t.Fatal(err)
	}
	provider := guard.authzProvider.(*OarkflowAuthzProvider)
	roles, err := provider.Engine().ListRolesForUser(context.Background(), "user:alice")
	if err != nil || !slicesEqual(roles, []string{"admin"}) {
		t.Fatalf("configured memberships not applied: roles=%v err=%v", roles, err)
	}
	handler := guard.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, tt := range []struct {
		subject string
		want    int
	}{{"user:alice", http.StatusOK}, {"user:bob", http.StatusForbidden}} {
		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		req.Header.Set("X-Subject-ID", tt.subject)
		req.Header.Set("X-Tenant-ID", "org1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Fatalf("subject=%s status=%d want=%d body=%s", tt.subject, rec.Code, tt.want, rec.Body.String())
		}
	}
}

func TestOarkflowAuthzProviderSplitsTypedRouteResource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcpguard.authz")
	if err := os.WriteFile(path, []byte(`
tenant bank "Demo Bank"
policy allow-payment-approvers bank allow POST route:POST:/payments/approve subject.roles@manager priority:90
role manager bank Manager POST:route:POST:/payments/approve
member user:manager-1 manager
engine cache_ttl=5000 attr_ttl=10000 batch_size=64 flush_interval=50 workers=0
`), 0o600); err != nil {
		t.Fatal(err)
	}

	provider, err := NewOarkflowAuthzProviderFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := provider.Authorize(context.Background(), AuthzRequest{
		Policy:   "allow-payment-approvers",
		Action:   "POST",
		Resource: "route:POST:/payments/approve",
		Subject: map[string]any{
			"id":        "manager-1",
			"tenant_id": "bank",
			"roles":     []string{"manager"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("allowed=false reason=%q matched_by=%q trace=%v", decision.Evidence.Reason, decision.Evidence.MatchedBy, decision.Evidence.Trace)
	}
}

func TestAuthzRolesIncludesSingularRole(t *testing.T) {
	roles := authzRoles(IdentityContext{Role: "manager", Roles: []string{"admin"}})
	if !slicesEqual(roles, []string{"admin", "manager"}) {
		t.Fatalf("roles=%v", roles)
	}
}

func TestFiberExampleAuthzAllowsDemoUsers(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	path := filepath.Join(filepath.Dir(file), "examples", "tcpguard_fiber_server", "tcpguard.authz")
	provider, err := NewOarkflowAuthzProviderFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := provider.Authorize(context.Background(), AuthzRequest{
		Action:   "GET",
		Resource: "route:GET:/public",
		Subject: map[string]any{
			"id":        "locked-user",
			"tenant_id": "demo-bank",
			"roles":     []string{"member"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("allowed=false reason=%q matched_by=%q trace=%v", decision.Evidence.Reason, decision.Evidence.MatchedBy, decision.Evidence.Trace)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
