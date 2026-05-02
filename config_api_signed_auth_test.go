package tcpguard

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

func TestConfigAPISignedAuthMiddleware(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, err := NewConfigAPISignedAuthToken(secret, ConfigAPIAuthIdentity{
		UserID:   "admin",
		Roles:    []string{ConfigRoleAdmin},
		Groups:   []string{"ops"},
		TenantID: "tenant-a",
	}, time.Minute)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthToken() error = %v", err)
	}
	mw, err := NewConfigAPISignedAuthMiddleware(secret)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthMiddleware() error = %v", err)
	}
	app := fiber.New()
	app.Use(mw)
	app.Get("/whoami", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user":   c.Locals("tcpguard.user_id"),
			"roles":  c.Locals("tcpguard.user_roles"),
			"groups": c.Locals("tcpguard.user_groups"),
			"tenant": c.Locals("tcpguard.tenant_id"),
		})
	})

	req := httptest.NewRequest("GET", "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestConfigAPISignedAuthRejectsInvalidTokens(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	mw, err := NewConfigAPISignedAuthMiddleware(secret)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthMiddleware() error = %v", err)
	}
	app := fiber.New()
	app.Use(mw)
	app.Get("/protected", func(c fiber.Ctx) error { return c.SendStatus(204) })

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("missing token app.Test() error = %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("missing token status = %d, want 401", resp.StatusCode)
	}

	token, err := NewConfigAPISignedAuthToken(secret, ConfigAPIAuthIdentity{UserID: "admin", Roles: []string{ConfigRoleAdmin}}, time.Minute)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthToken() error = %v", err)
	}
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token+"tampered")
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("tampered token app.Test() error = %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("tampered token status = %d, want 401", resp.StatusCode)
	}
}

func TestConfigAPISignedAuthExpiryAndRevocation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now().UTC()
	token, err := NewConfigAPISignedAuthToken(
		secret,
		ConfigAPIAuthIdentity{UserID: "admin", Roles: []string{ConfigRoleAdmin}},
		time.Minute,
		func(cfg *configAPISignedAuthConfig) { cfg.now = func() time.Time { return now } },
	)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthToken() error = %v", err)
	}
	mw, err := NewConfigAPISignedAuthMiddleware(
		secret,
		WithConfigAPISignedAuthLeeway(0),
		func(cfg *configAPISignedAuthConfig) { cfg.now = func() time.Time { return now.Add(2 * time.Minute) } },
	)
	if err != nil {
		t.Fatalf("NewConfigAPISignedAuthMiddleware() error = %v", err)
	}
	app := fiber.New()
	app.Use(mw)
	app.Get("/protected", func(c fiber.Ctx) error { return c.SendStatus(204) })
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("expired token app.Test() error = %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expired token status = %d, want 401", resp.StatusCode)
	}

	tokenID := tokenIDFromToken(t, token)
	mw, err = NewConfigAPISignedAuthMiddleware(secret, WithConfigAPISignedAuthRevocation(func(id string) (bool, error) {
		return id == tokenID, nil
	}))
	if err != nil {
		t.Fatalf("revocation middleware error = %v", err)
	}
	app = fiber.New()
	app.Use(mw)
	app.Get("/protected", func(c fiber.Ctx) error { return c.SendStatus(204) })
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("revoked token app.Test() error = %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("revoked token status = %d, want 401", resp.StatusCode)
	}
}

func TestConfigAPISignedAuthRejectsShortSecret(t *testing.T) {
	_, err := NewConfigAPISignedAuthMiddleware([]byte("short"))
	if err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short middleware secret error = %v, want length error", err)
	}
	_, err = NewConfigAPISignedAuthToken([]byte("short"), ConfigAPIAuthIdentity{UserID: "admin"}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short token secret error = %v, want length error", err)
	}
}

func tokenIDFromToken(t *testing.T, token string) string {
	t.Helper()
	claims, err := parseConfigAPISignedAuthToken([]byte("0123456789abcdef0123456789abcdef"), token, defaultConfigAPISignedAuthConfig())
	if err != nil {
		t.Fatalf("parse token error = %v", err)
	}
	return claims.ID
}
