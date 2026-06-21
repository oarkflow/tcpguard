package fiber_test

import (
	"net/http"
	"testing"

	gofiber "github.com/gofiber/fiber/v3"
	"github.com/oarkflow/tcpguard"
	tcpguardfiber "github.com/oarkflow/tcpguard/adapters/fiber"
)

func TestMiddlewareBlocksRequest(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{DisableGeoIP: true}),
		tcpguard.WithRule(tcpguard.Rule{
			ID: "block-admin", Status: tcpguard.RuleActive,
			Triggers: []string{"request.received"}, Scope: tcpguard.Scope{Paths: []string{"/admin/*"}},
			Risk:     tcpguard.RiskSpec{Base: 100, Max: 100},
			Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	app := gofiber.New()
	app.Use(tcpguardfiber.Middleware(guard))
	app.Get("/admin/users", func(c gofiber.Ctx) error { return c.SendString("ok") })
	resp, err := app.Test(mustRequest(t, http.MethodGet, "/admin/users"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
