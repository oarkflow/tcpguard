package tcpguard

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

func TestRuleSkipMatcherSkipsAnyRuleType(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	pipelineReg := NewInMemoryPipelineFunctionRegistry()
	pipelineReg.Register("always", func(ctx *Context) any { return true })

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				Rules: map[string]Rule{
					"skippable": {
						Name:    "skippable",
						Type:    "always",
						Enabled: true,
						Skip: []RequestMatcher{
							{
								Name: "signed-client",
								All: []RequestMatcher{
									{HeaderKeys: []string{"X-Gate-Signature"}},
									{HeaderKeys: []string{"X-Capability-Token"}},
								},
							},
						},
						Actions: []Action{{
							Type:     "rate_limit",
							Priority: 1,
							Response: Response{Status: 429, Message: "limited"},
						}},
					},
				},
			},
			APIEndpoints: map[string]EndpointRules{},
		},
	}

	re, err := NewRuleEngineWithConfig(config, store, NewTokenBucketRateLimiter(100, time.Minute), NewActionHandlerRegistry(), pipelineReg, NewInMemoryMetricsCollector(), nil)
	if err != nil {
		t.Fatalf("NewRuleEngineWithConfig failed: %v", err)
	}

	app := fiber.New()
	app.Use(re.AnomalyDetectionMiddleware())
	app.Get("/api/me", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("X-Gate-Signature", "opaque")
	req.Header.Set("X-Capability-Token", "opaque")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("signed request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("signed request status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}

	req = httptest.NewRequest("GET", "/api/me", nil)
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("unsigned request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != fiber.StatusTooManyRequests {
		t.Fatalf("unsigned request status = %d, want %d", resp.StatusCode, fiber.StatusTooManyRequests)
	}
}

func TestRequestMatcherSupportsFilesUsersGroupsAndValues(t *testing.T) {
	app, c := acquireTestContext("GET", "/assets/app.js")
	defer releaseTestContext(app, c)

	c.Request().Header.Set("Accept", "text/javascript")
	c.Request().Header.Set("X-Client", "web-browser")

	matcher := RequestMatcher{
		Methods:        []string{"GET"},
		FileExtensions: []string{".js", ".css"},
		Headers:        map[string][]string{"X-Client": []string{"web-*"}},
		Accepts:        []string{"*javascript*"},
		Users:          []string{"alice"},
		Groups:         []string{"customers"},
	}
	if !requestMatches(c, "alice", []string{"customers"}, matcher) {
		t.Fatal("expected request matcher to match file, values, user, and group")
	}
	if requestMatches(c, "bob", []string{"customers"}, matcher) {
		t.Fatal("expected request matcher to reject unmatched user")
	}
}

func TestInjectionSkipFieldsAreConfigDriven(t *testing.T) {
	app, c := acquireTestContext("POST", "/api/me")
	defer releaseTestContext(app, c)

	c.Request().Header.Set("X-Signed-Token", "v1|opaque|signature")

	ctx := &Context{
		RuleEngine: &RuleEngine{},
		FiberCtx:   c,
		Results: map[string]any{
			"scanTargets": []string{"headers"},
			"skipFields": []map[string]any{
				{
					"targets": []string{"headers"},
					"fields":  []string{"x-signed-*"},
					"types":   []string{"command_injection"},
				},
			},
		},
	}

	if triggered, ok := InjectionDetectionCondition(ctx).(bool); !ok || triggered {
		t.Fatalf("expected configured header skip to avoid false positive, got %#v", ctx.Results["injectionVerdict"])
	}
}
