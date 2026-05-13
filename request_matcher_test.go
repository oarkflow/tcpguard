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

func TestTrustedClientCIDRBypassSkipsGlobalDetectorsAndEndpointRateLimit(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	pipelineReg := NewInMemoryPipelineFunctionRegistry()
	pipelineReg.Register("always", func(ctx *Context) any { return true })

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				TrustProxy:        true,
				TrustedProxyCIDRs: []string{"0.0.0.0/32"},
				TrustedClientBypass: &TrustedClientBypassConfig{
					Matchers: []RequestMatcher{{Name: "internal-client", ClientCIDRs: []string{"10.10.0.0/16"}}},
				},
				Rules: map[string]Rule{
					"detector": {
						Name:    "detector",
						Type:    "always",
						Enabled: true,
						Actions: []Action{{
							Type:     "rate_limit",
							Priority: 1,
							Response: Response{Status: 429, Message: "detector limited"},
						}},
					},
				},
			},
			APIEndpoints: map[string]EndpointRules{
				"/api/me": {
					Name:      "me",
					Endpoint:  "/api/me",
					RateLimit: RateLimit{RequestsPerMinute: 0},
					Actions: []Action{{
						Type:     "rate_limit",
						Priority: 1,
						Response: Response{Status: 429, Message: "endpoint limited"},
					}},
				},
			},
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
	req.Header.Set("X-Forwarded-For", "10.10.1.20")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("trusted request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("trusted request status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}
	if counter, err := store.GetGlobal("10.10.1.20"); err != nil {
		t.Fatalf("GetGlobal failed: %v", err)
	} else if counter != nil {
		t.Fatalf("trusted request should not increment global counter, got %#v", counter)
	}
	if counter, err := store.GetEndpoint("10.10.1.20", "/api/me"); err != nil {
		t.Fatalf("GetEndpoint failed: %v", err)
	} else if counter != nil {
		t.Fatalf("trusted request should not increment endpoint counter, got %#v", counter)
	}

	req = httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("X-Forwarded-For", "10.20.1.20")
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("untrusted request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != fiber.StatusTooManyRequests {
		t.Fatalf("untrusted request status = %d, want %d", resp.StatusCode, fiber.StatusTooManyRequests)
	}
}

func TestTrustedClientHeaderBypassSkipsEndpointRateLimit(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				TrustedClientBypass: &TrustedClientBypassConfig{
					Matchers: []RequestMatcher{{
						Name: "signed-internal-client",
						All: []RequestMatcher{
							{HeaderKeys: []string{"X-Trusted-Client"}},
							{Headers: map[string][]string{"X-Trusted-Client": {"tcpguard-internal"}}},
						},
					}},
				},
				Rules: map[string]Rule{},
			},
			APIEndpoints: map[string]EndpointRules{
				"/api/me": {
					Name:      "me",
					Endpoint:  "/api/me",
					RateLimit: RateLimit{RequestsPerMinute: 0},
					Actions: []Action{{
						Type:     "rate_limit",
						Priority: 1,
						Response: Response{Status: 429, Message: "endpoint limited"},
					}},
				},
			},
		},
	}

	re, err := NewRuleEngineWithConfig(config, store, NewTokenBucketRateLimiter(100, time.Minute), NewActionHandlerRegistry(), NewInMemoryPipelineFunctionRegistry(), NewInMemoryMetricsCollector(), nil)
	if err != nil {
		t.Fatalf("NewRuleEngineWithConfig failed: %v", err)
	}

	app := fiber.New()
	app.Use(re.AnomalyDetectionMiddleware())
	app.Get("/api/me", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Trusted-Client", "tcpguard-internal")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("trusted header request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("trusted header request status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}
}

func TestTrustedClientBypassDoesNotSkipDenyListOrBans(t *testing.T) {
	t.Run("deny list wins", func(t *testing.T) {
		store := NewInMemoryCounterStore()
		defer store.StopCleanup()

		config := &AnomalyConfig{
			AnomalyDetectionRules: AnomalyDetectionRules{
				Global: GlobalRules{
					TrustProxy:        true,
					TrustedProxyCIDRs: []string{"0.0.0.0/32"},
					DenyCIDRs:         []string{"10.10.0.0/16"},
					TrustedClientBypass: &TrustedClientBypassConfig{
						Matchers: []RequestMatcher{{ClientCIDRs: []string{"10.10.0.0/16"}}},
					},
					Rules: map[string]Rule{},
				},
				APIEndpoints: map[string]EndpointRules{},
			},
		}
		re, err := NewRuleEngineWithConfig(config, store, NewTokenBucketRateLimiter(100, time.Minute), NewActionHandlerRegistry(), NewInMemoryPipelineFunctionRegistry(), NewInMemoryMetricsCollector(), nil)
		if err != nil {
			t.Fatalf("NewRuleEngineWithConfig failed: %v", err)
		}

		app := fiber.New()
		app.Use(re.AnomalyDetectionMiddleware())
		app.Get("/api/me", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

		req := httptest.NewRequest("GET", "/api/me", nil)
		req.Header.Set("X-Forwarded-For", "10.10.1.20")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("denied request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != fiber.StatusForbidden {
			t.Fatalf("denied request status = %d, want %d", resp.StatusCode, fiber.StatusForbidden)
		}
	})

	t.Run("ban wins", func(t *testing.T) {
		store := NewInMemoryCounterStore()
		defer store.StopCleanup()
		if err := store.SetBan("10.10.1.20", &BanInfo{Until: time.Now().Add(time.Minute), Reason: "banned", StatusCode: 403}); err != nil {
			t.Fatalf("SetBan failed: %v", err)
		}

		config := &AnomalyConfig{
			AnomalyDetectionRules: AnomalyDetectionRules{
				Global: GlobalRules{
					TrustProxy:        true,
					TrustedProxyCIDRs: []string{"0.0.0.0/32"},
					TrustedClientBypass: &TrustedClientBypassConfig{
						Matchers: []RequestMatcher{{ClientCIDRs: []string{"10.10.0.0/16"}}},
					},
					Rules: map[string]Rule{},
				},
				APIEndpoints: map[string]EndpointRules{},
			},
		}
		re, err := NewRuleEngineWithConfig(config, store, NewTokenBucketRateLimiter(100, time.Minute), NewActionHandlerRegistry(), NewInMemoryPipelineFunctionRegistry(), NewInMemoryMetricsCollector(), nil)
		if err != nil {
			t.Fatalf("NewRuleEngineWithConfig failed: %v", err)
		}

		app := fiber.New()
		app.Use(re.AnomalyDetectionMiddleware())
		app.Get("/api/me", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

		req := httptest.NewRequest("GET", "/api/me", nil)
		req.Header.Set("X-Forwarded-For", "10.10.1.20")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("banned request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != fiber.StatusForbidden {
			t.Fatalf("banned request status = %d, want %d", resp.StatusCode, fiber.StatusForbidden)
		}
	})
}

func TestTrustedClientCIDRBypassUsesTrustedProxyClientIP(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	pipelineReg := NewInMemoryPipelineFunctionRegistry()
	pipelineReg.Register("always", func(ctx *Context) any { return true })

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				TrustProxy:        true,
				TrustedProxyCIDRs: []string{"0.0.0.0/32"},
				TrustedClientBypass: &TrustedClientBypassConfig{
					Matchers: []RequestMatcher{{ClientCIDRs: []string{"198.51.100.0/24"}}},
				},
				Rules: map[string]Rule{
					"detector": {
						Name:    "detector",
						Type:    "always",
						Enabled: true,
						Actions: []Action{{
							Type:     "rate_limit",
							Priority: 1,
							Response: Response{Status: 429, Message: "detector limited"},
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
	req.Header.Set("X-Forwarded-For", "198.51.100.25")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("trusted proxy request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("trusted proxy request status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}
}
