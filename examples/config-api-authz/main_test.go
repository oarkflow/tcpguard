package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/tcpguard"
)

func TestConfigAPIAuthzExample(t *testing.T) {
	app, _, emitter, err := newApp(t.TempDir())
	if err != nil {
		t.Fatalf("newApp() error = %v", err)
	}

	assertStatus(t, app, request("GET", "/api/rules", "", "", ""), 403)
	assertStatus(t, app, request("GET", "/api/rules", "", "viewer", tcpguard.ConfigRoleViewer), 200)

	validRule := `{"name":"exampleRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	assertStatus(t, app, request("POST", "/api/rules", validRule, "viewer", tcpguard.ConfigRoleViewer), 403)

	resp := assertStatus(t, app, request("POST", "/api/rules", validRule, "editor", tcpguard.ConfigRoleEditor), 201)
	version := resp.Header.Get("X-Config-Version")
	if version == "" {
		t.Fatal("editor create did not return X-Config-Version")
	}

	updateBlockedRule := `{"name":"blockedRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	assertStatus(t, app, request("PUT", "/api/rules/blockedRule", updateBlockedRule, "editor", tcpguard.ConfigRoleEditor), 403)

	stale := request("PUT", "/api/rules/exampleRule", validRule, "editor", tcpguard.ConfigRoleEditor)
	stale.Header.Set("If-Match", "1")
	assertStatus(t, app, stale, 409)

	roleJSON := `{"id":"demo_role","tenant_id":"default","name":"Demo","permissions":[{"action":"get","resource":"config.rule:*"}]}`
	assertStatus(t, app, request("POST", "/api/authz/roles", roleJSON, "editor", tcpguard.ConfigRoleEditor), 403)
	assertStatus(t, app, request("POST", "/api/authz/roles", roleJSON, "admin", tcpguard.ConfigRoleAdmin), 201)

	events, err := emitter.Query(nil, tcpguard.EventFilter{Limit: 20})
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events from example requests")
	}
}

func request(method, path, body, userID, roles string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if userID != "" {
		req.Header.Set("X-Demo-User", userID)
	}
	if roles != "" {
		req.Header.Set("X-Demo-Roles", roles)
	}
	return req
}

func assertStatus(t *testing.T, app *fiber.App, req *http.Request, want int) *http.Response {
	t.Helper()
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("%s %s error = %v", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s status = %d, want %d: %s", req.Method, req.URL.Path, resp.StatusCode, want, body)
	}
	return resp
}
