package tcpguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChainAuthProvider(t *testing.T) {
	auth := ChainAuthProvider{
		StaticAPIKeyAuth{
			Keys: map[string]ManagementPrincipal{
				"good-key": {Subject: "ops", Roles: []string{"admin"}},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-API-Key", "good-key")
	p, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("expected auth success, got %v", err)
	}
	if p.Subject != "ops" {
		t.Fatalf("unexpected subject: %s", p.Subject)
	}
}

func TestRoleBasedAuthorizer(t *testing.T) {
	authz := RoleBasedAuthorizer{
		RolesByRoute: map[ManagementRoute][]string{
			ManagementRouteReload: {"admin"},
		},
	}
	if authz.Authorize(ManagementRouteReload, ManagementPrincipal{Roles: []string{"viewer"}}) {
		t.Fatal("expected authorization deny")
	}
	if !authz.Authorize(ManagementRouteReload, ManagementPrincipal{Roles: []string{"admin"}}) {
		t.Fatal("expected authorization allow")
	}
}

func TestPaginationQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit?limit=2&cursor=1", nil)
	items := []Incident{
		{ID: "a"}, {ID: "b"}, {ID: "c"},
	}
	q := parsePaginationQuery(req, 10)
	out := paginateItems(items, q, func(v Incident) time.Time { return v.CreatedAt })
	if len(out.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(out.Items))
	}
	if out.Items[0].ID != "b" {
		t.Fatalf("unexpected first item: %s", out.Items[0].ID)
	}
}
