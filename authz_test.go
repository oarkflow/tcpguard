package tcpguard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

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
