package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/tcpguard"
)

func TestProductionReadyExample(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	csrf := "csrf-test-token"
	bundle, err := newProductionApp(productionSettings{
		DBPath:            t.TempDir() + "/tcpguard.db",
		AuthSecret:        secret,
		CSRFToken:         csrf,
		TrustedProxyCIDRs: []string{"127.0.0.1/32", "::1/128"},
	})
	if err != nil {
		t.Fatalf("newProductionApp() error = %v", err)
	}
	defer bundle.db.Close()

	viewer := tokenFor(t, secret, "viewer", tcpguard.ConfigRoleViewer)
	editor := tokenFor(t, secret, "editor", tcpguard.ConfigRoleEditor)
	admin := tokenFor(t, secret, "admin", tcpguard.ConfigRoleAdmin)

	assertStatus(t, bundle.app, request("GET", "/ready", "", ""), 200)
	assertStatus(t, bundle.app, request("GET", "/api/rules", "", ""), 401)
	assertStatus(t, bundle.app, request("GET", "/api/rules", "", viewer), 200)

	rule := `{"name":"productionExampleRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}`
	assertStatus(t, bundle.app, request("POST", "/api/rules", rule, viewer), 403)

	mutation := request("POST", "/api/rules", rule, editor)
	mutation.Header.Set("Origin", "https://admin.example.com")
	mutation.Header.Set("X-CSRF-Token", csrf)
	resp := assertStatus(t, bundle.app, mutation, 201)
	if resp.Header.Get("X-Config-Version") == "" {
		t.Fatal("mutation did not return X-Config-Version")
	}

	assertStatus(t, bundle.app, request("POST", "/api/authz/roles", `{"id":"x","tenant_id":"default","name":"X"}`, editor), 403)
	assertStatus(t, bundle.app, request("GET", "/api/authz/roles", "", admin), 200)
	assertStatus(t, bundle.app, request("GET", "/api/audit", "", admin), 200)

	readyResp := assertStatus(t, bundle.app, request("GET", "/ready", "", ""), 200)
	var report tcpguard.ProductionReadinessReport
	if err := json.NewDecoder(readyResp.Body).Decode(&report); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if !report.Ready {
		t.Fatalf("readiness report not ready: %+v", report)
	}
}

func request(method, path, body, token string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func tokenFor(t *testing.T, secret []byte, userID string, roles ...string) string {
	t.Helper()
	token, err := tcpguard.NewConfigAPISignedAuthToken(secret, tcpguard.ConfigAPIAuthIdentity{
		UserID:   userID,
		Roles:    roles,
		TenantID: "default",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthToken(%s) error = %v", userID, err)
	}
	return token
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
