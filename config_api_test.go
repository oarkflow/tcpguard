package tcpguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/authz"
)

func newConfigAPITestStore(t *testing.T) *FileConfigStore {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"rules", "endpoints", "global"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	store, err := NewFileConfigStore(dir)
	if err != nil {
		t.Fatalf("NewFileConfigStore() error = %v", err)
	}
	return store
}

func TestConfigAPISecureByDefault(t *testing.T) {
	store := newConfigAPITestStore(t)
	api := NewConfigAPI(store)
	app := fiber.New()
	api.RegisterRoutes(app)

	req := httptest.NewRequest("GET", "/api/rules", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestConfigAPIAdminTokenValidationVersionAndAudit(t *testing.T) {
	store := newConfigAPITestStore(t)
	emitter := NewInMemoryEventEmitter(20)
	api := NewConfigAPI(
		store,
		WithConfigAPIAdminToken("secret-admin-token"),
		WithConfigAPIValidator(NewDefaultConfigValidator()),
		WithConfigAPIEventEmitter(emitter),
	)
	app := fiber.New()
	api.RegisterRoutes(app)

	invalid := `{"name":"","type":"ddos","enabled":true,"actions":[]}`
	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(invalid))
	req.Header.Set("Authorization", "Bearer secret-admin-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test(invalid) error = %v", err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("invalid config status = %d, want 400", resp.StatusCode)
	}

	valid := `{"name":"ddosDetection","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	req = httptest.NewRequest("POST", "/api/rules?version=1", strings.NewReader(valid))
	req.Header.Set("Authorization", "Bearer secret-admin-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Config-If-Match", "1")
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("app.Test(valid) error = %v", err)
	}
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid config status = %d, want 201: %s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("X-Config-Version"); got != "2" {
		t.Fatalf("X-Config-Version = %q, want 2", got)
	}
	if api.version != 2 {
		t.Fatalf("api.version = %d, want 2", api.version)
	}

	ctxApp, c := acquireTestContext("POST", "/api/rules")
	defer releaseTestContext(ctxApp, c)
	if handled := api.checkVersionValue(c, "1"); !handled {
		t.Fatal("checkVersionValue() handled = false, want conflict response")
	}

	events, err := emitter.Query(nil, EventFilter{Types: []string{"config_api_create"}, Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("audit events = %d, want at least 2", len(events))
	}
}

func newConfigAPIAuthzTestApp(t *testing.T) (*fiber.App, *FileConfigStore, *authz.Engine, *InMemoryEventEmitter) {
	t.Helper()
	store := newConfigAPITestStore(t)
	engine := NewDefaultConfigAPIAuthzEngine()
	emitter := NewInMemoryEventEmitter(50)
	api := NewConfigAPI(store, WithConfigAPIAuthz(engine, HeaderConfigAPIAuthzResolver), WithConfigAPIValidator(NewDefaultConfigValidator()), WithConfigAPIEventEmitter(emitter))
	app := fiber.New()
	api.RegisterRoutes(app)
	return app, store, engine, emitter
}

func addValidRule(t *testing.T, store ConfigStore, name string) {
	t.Helper()
	err := store.CreateRule(&Rule{
		Name:    name,
		Type:    "ddos",
		Enabled: true,
		Actions: []Action{{
			Type:     "temporary_ban",
			Duration: "10m",
			Response: Response{Status: 403, Message: "blocked"},
		}},
	})
	if err != nil {
		t.Fatalf("CreateRule(%s) error = %v", name, err)
	}
}

func authzReq(method, path, body, userID, roles string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Roles", roles)
	return req
}

func TestConfigAPIAuthzRBACViewerEditorAdmin(t *testing.T) {
	app, store, _, _ := newConfigAPIAuthzTestApp(t)
	addValidRule(t, store, "existing")

	resp, err := app.Test(authzReq("GET", "/api/rules", "", "viewer", ConfigRoleViewer))
	if err != nil {
		t.Fatalf("viewer list error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("viewer list status = %d, want 200", resp.StatusCode)
	}

	valid := `{"name":"newRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	resp, err = app.Test(authzReq("POST", "/api/rules", valid, "viewer", ConfigRoleViewer))
	if err != nil {
		t.Fatalf("viewer create error = %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("viewer create status = %d, want 403", resp.StatusCode)
	}

	resp, err = app.Test(authzReq("POST", "/api/rules", valid, "editor", ConfigRoleEditor))
	if err != nil {
		t.Fatalf("editor create error = %v", err)
	}
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("editor create status = %d, want 201: %s", resp.StatusCode, body)
	}

	roleJSON := `{"id":"custom_role","tenant_id":"default","name":"Custom","permissions":[{"action":"get","resource":"config.rule:*"}]}`
	resp, err = app.Test(authzReq("POST", "/api/authz/roles", roleJSON, "editor", ConfigRoleEditor))
	if err != nil {
		t.Fatalf("editor authz role create error = %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("editor authz role create status = %d, want 403", resp.StatusCode)
	}

	resp, err = app.Test(authzReq("POST", "/api/authz/roles", roleJSON, "admin", ConfigRoleAdmin))
	if err != nil {
		t.Fatalf("admin authz role create error = %v", err)
	}
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin authz role create status = %d, want 201: %s", resp.StatusCode, body)
	}
}

func TestConfigAPIAuthzACLDenyOverridesRBACAllow(t *testing.T) {
	app, store, engine, _ := newConfigAPIAuthzTestApp(t)
	addValidRule(t, store, "blockedRule")
	err := engine.GrantACL(context.Background(), &authz.ACL{
		ID:         "deny-editor-blocked-rule",
		TenantID:   "default",
		ResourceID: "blockedRule",
		SubjectID:  "editor",
		Actions:    []authz.Action{"update"},
		Effect:     authz.EffectDeny,
	})
	if err != nil {
		t.Fatalf("GrantACL() error = %v", err)
	}

	body := `{"name":"blockedRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	resp, err := app.Test(authzReq("PUT", "/api/rules/blockedRule", body, "editor", ConfigRoleEditor))
	if err != nil {
		t.Fatalf("editor update with deny ACL error = %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("editor update with deny ACL status = %d, want 403", resp.StatusCode)
	}
}

func TestConfigAPIAuthzACLAllowGrantsResourceAccess(t *testing.T) {
	app, store, engine, _ := newConfigAPIAuthzTestApp(t)
	addValidRule(t, store, "readableRule")
	err := engine.GrantACL(context.Background(), &authz.ACL{
		ID:         "allow-alice-readable-rule",
		TenantID:   "default",
		ResourceID: "readableRule",
		SubjectID:  "alice",
		Actions:    []authz.Action{"get"},
		Effect:     authz.EffectAllow,
	})
	if err != nil {
		t.Fatalf("GrantACL() error = %v", err)
	}

	resp, err := app.Test(authzReq("GET", "/api/rules/readableRule", "", "alice", ""))
	if err != nil {
		t.Fatalf("alice get with allow ACL error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("alice get with allow ACL status = %d, want 200", resp.StatusCode)
	}
}

func TestConfigAPIAuthzABACDenyUntrustedIP(t *testing.T) {
	app, _, engine, _ := newConfigAPIAuthzTestApp(t)
	err := engine.CreatePolicy(context.Background(), &authz.Policy{
		ID:        "deny-local-race-ip",
		TenantID:  "default",
		Effect:    authz.EffectDeny,
		Actions:   []authz.Action{"create"},
		Resources: []string{"config.rule:*"},
		Condition: &authz.CIDRExpr{CIDR: "0.0.0.0/32"},
		Priority:  1000,
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	valid := `{"name":"deniedByABAC","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	resp, err := app.Test(authzReq("POST", "/api/rules", valid, "editor", ConfigRoleEditor))
	if err != nil {
		t.Fatalf("editor create with ABAC deny error = %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("editor create with ABAC deny status = %d, want 403", resp.StatusCode)
	}
}

func TestConfigAPIAuthzAuditIncludesDecision(t *testing.T) {
	app, _, _, emitter := newConfigAPIAuthzTestApp(t)
	resp, err := app.Test(authzReq("GET", "/api/rules", "", "viewer", ConfigRoleViewer))
	if err != nil {
		t.Fatalf("viewer list error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("viewer list status = %d, want 200", resp.StatusCode)
	}
	events, err := emitter.Query(nil, EventFilter{Types: []string{"config_api_list"}, Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected config_api_list audit event")
	}
	if _, ok := events[0].Details["authz"]; !ok {
		t.Fatalf("audit details missing authz decision: %#v", events[0].Details)
	}
}

func TestConfigAPIFileVersionPersistsAcrossInstances(t *testing.T) {
	store := newConfigAPITestStore(t)
	api := NewConfigAPI(store, WithConfigAPIUnsafePublicAccess(), WithConfigAPIValidator(NewDefaultConfigValidator()))
	app := fiber.New()
	api.RegisterRoutes(app)
	valid := `{"name":"fileVersionRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(valid))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("file version create error = %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("file version create status = %d, want 201", resp.StatusCode)
	}
	version, err := store.GetConfigVersion()
	if err != nil {
		t.Fatalf("GetConfigVersion() error = %v", err)
	}
	store2, err := NewFileConfigStore(store.configDir)
	if err != nil {
		t.Fatalf("NewFileConfigStore() error = %v", err)
	}
	api2 := NewConfigAPI(store2, WithConfigAPIUnsafePublicAccess())
	if api2.currentVersion() != version {
		t.Fatalf("persisted file version = %d, want %d", api2.currentVersion(), version)
	}
}

func TestConfigAPISQLVersionPersistsAcrossInstances(t *testing.T) {
	db, err := sqlx.Connect("sqlite3", filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatalf("sql connect error = %v", err)
	}
	defer db.Close()
	store, err := NewSQLConfigStore(db)
	if err != nil {
		t.Fatalf("NewSQLConfigStore() error = %v", err)
	}
	next, err := store.CompareAndSwapConfigVersion(1)
	if err != nil {
		t.Fatalf("CompareAndSwapConfigVersion() error = %v", err)
	}
	if next != 2 {
		t.Fatalf("next version = %d, want 2", next)
	}
	store2, err := NewSQLConfigStore(db)
	if err != nil {
		t.Fatalf("NewSQLConfigStore(second) error = %v", err)
	}
	version, err := store2.GetConfigVersion()
	if err != nil {
		t.Fatalf("GetConfigVersion() error = %v", err)
	}
	if version != 2 {
		t.Fatalf("persisted sql version = %d, want 2", version)
	}
}
