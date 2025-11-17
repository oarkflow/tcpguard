package tcpguard

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func TestInMemoryCounterStore(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	// Test IncrementGlobal
	count, _, err := store.IncrementGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("IncrementGlobal failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected count 1, got %d", count)
	}

	// Test GetGlobal
	counter, err := store.GetGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("GetGlobal failed: %v", err)
	}
	if counter == nil {
		t.Fatal("Expected counter, got nil")
	}
	if counter.Count != 1 {
		t.Errorf("Expected count 1, got %d", counter.Count)
	}

	// Test ResetGlobal
	err = store.ResetGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("ResetGlobal failed: %v", err)
	}

	counter, err = store.GetGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("GetGlobal after reset failed: %v", err)
	}
	if counter != nil {
		t.Errorf("Expected nil after reset, got %v", counter)
	}
}

func TestInMemoryCounterStore_IncrementEndpoint(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	// Test IncrementEndpoint
	counter, err := store.IncrementEndpoint("192.168.1.1", "/api/login")
	if err != nil {
		t.Fatalf("IncrementEndpoint failed: %v", err)
	}
	if counter.Count != 1 {
		t.Errorf("Expected count 1, got %d", counter.Count)
	}
	if counter.Burst != 1 {
		t.Errorf("Expected burst 1, got %d", counter.Burst)
	}

	// Test GetEndpoint
	retrieved, err := store.GetEndpoint("192.168.1.1", "/api/login")
	if err != nil {
		t.Fatalf("GetEndpoint failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected counter, got nil")
	}
	if retrieved.Count != 1 {
		t.Errorf("Expected count 1, got %d", retrieved.Count)
	}
}

func TestInMemoryCounterStore_BanOperations(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	ban := &BanInfo{
		Until:      time.Now().Add(time.Hour),
		Permanent:  false,
		Reason:     "Test ban",
		StatusCode: 403,
	}

	// Test SetBan
	err := store.SetBan("192.168.1.1", ban)
	if err != nil {
		t.Fatalf("SetBan failed: %v", err)
	}

	// Test GetBan
	retrieved, err := store.GetBan("192.168.1.1")
	if err != nil {
		t.Fatalf("GetBan failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected ban info, got nil")
	}
	if retrieved.Reason != "Test ban" {
		t.Errorf("Expected reason 'Test ban', got '%s'", retrieved.Reason)
	}

	// Test DeleteBan
	err = store.DeleteBan("192.168.1.1")
	if err != nil {
		t.Fatalf("DeleteBan failed: %v", err)
	}

	retrieved, err = store.GetBan("192.168.1.1")
	if err != nil {
		t.Fatalf("GetBan after delete failed: %v", err)
	}
	if retrieved != nil {
		t.Errorf("Expected nil after delete, got %v", retrieved)
	}
}

func TestDefaultConfigValidator(t *testing.T) {
	validator := NewDefaultConfigValidator()

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				Rules: map[string]Rule{
					"test_rule": {
						Name:    "test_rule",
						Type:    "test",
						Enabled: true,
						Actions: []Action{
							{
								Type: "rate_limit",
								Response: Response{
									Status:  429,
									Message: "Rate limited",
								},
							},
						},
					},
				},
			},
			APIEndpoints: map[string]EndpointRules{
				"/api/test": {
					Name:      "test_endpoint",
					Endpoint:  "/api/test",
					RateLimit: RateLimit{RequestsPerMinute: 10},
					Actions: []Action{
						{
							Type: "rate_limit",
							Response: Response{
								Status:  429,
								Message: "Rate limited",
							},
						},
					},
				},
			},
		},
	}

	err := validator.Validate(config)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}
}

func TestInMemoryPipelineFunctionRegistry(t *testing.T) {
	reg := NewInMemoryPipelineFunctionRegistry()

	// Test Register and Get
	fn := func(ctx *Context) any {
		return "test_result"
	}

	reg.Register("test_function", fn)

	retrieved, exists := reg.Get("test_function")
	if !exists {
		t.Fatal("Expected function to exist")
	}

	if retrieved == nil {
		t.Fatal("Expected function, got nil")
	}

	// Test non-existent function
	_, exists = reg.Get("non_existent")
	if exists {
		t.Fatal("Expected function to not exist")
	}
}

func TestInMemoryMetricsCollector(t *testing.T) {
	collector := NewInMemoryMetricsCollector()

	labels := map[string]string{"endpoint": "/api/test", "method": "POST"}

	// Test IncrementCounter
	collector.IncrementCounter("requests_total", labels)

	value := collector.GetCounterValue("requests_total", labels)
	if value != 1 {
		t.Errorf("Expected counter value 1, got %d", value)
	}

	// Test ObserveHistogram
	collector.ObserveHistogram("request_duration", 0.5, labels)

	// Test SetGauge
	collector.SetGauge("active_connections", 10.0, labels)

	gaugeValue := collector.GetGaugeValue("active_connections", 10.0, labels)
	if gaugeValue != 10.0 {
		t.Errorf("Expected gauge value 10.0, got %f", gaugeValue)
	}
}

func TestRegisterDefaultPipelineFunctions(t *testing.T) {
	reg := NewInMemoryPipelineFunctionRegistry()
	registerDefaultPipelineFunctions(reg)
	if _, exists := reg.Get("checkSessionHijacking"); !exists {
		t.Fatal("expected built-in session hijacking function to be registered")
	}
	if _, exists := reg.Get("mitm"); !exists {
		t.Fatal("expected built-in MITM detector to be registered")
	}
}

func TestPipelineCheckBusinessHours(t *testing.T) {
	app, c := acquireTestContext("GET", "/api/login")
	defer releaseTestContext(app, c)
	now := time.Now().UTC()
	ctx := &Context{
		FiberCtx: c,
		Results: map[string]any{
			"endpoint":    "/api/login",
			"timezone":    "UTC",
			"parse_start": now.Add(1 * time.Hour),
			"parse_end":   now.Add(2 * time.Hour),
		},
	}
	if !pipelineCheckBusinessHours(ctx).(bool) {
		t.Fatal("expected business hours check to trigger outside window")
	}
}

func TestPipelineProtectedRoute(t *testing.T) {
	app, c := acquireTestContext("GET", "/api/protected")
	defer releaseTestContext(app, c)
	ctx := &Context{
		FiberCtx: c,
		Results: map[string]any{
			"protectedRoutes":  []any{"/api/protected"},
			"loginCheckHeader": "Authorization",
		},
	}
	if !pipelineCheckProtectedRoute(ctx).(bool) {
		t.Fatal("expected missing auth header to trigger protected route condition")
	}
	c.Request().Header.Set("Authorization", "Bearer token")
	if pipelineCheckProtectedRoute(ctx).(bool) {
		t.Fatal("expected provided header to satisfy protected route condition")
	}
}

func TestPipelineSessionHijacking(t *testing.T) {
	app, c := acquireTestContext("GET", "/api/protected")
	defer releaseTestContext(app, c)
	store := NewInMemoryCounterStore()
	re := &RuleEngine{Store: store}
	now := time.Now()
	store.PutSessions("user-1", []*SessionInfo{{
		UA:       "agent-a",
		Created:  now.Add(-1 * time.Minute),
		LastSeen: now.Add(-1 * time.Minute),
	}})
	c.Request().Header.Set("X-User-ID", "user-1")
	ctx := &Context{
		RuleEngine: re,
		FiberCtx:   c,
		Results: map[string]any{
			"sessionTimeout":        "24h",
			"maxConcurrentSessions": float64(1),
		},
	}
	c.Request().Header.Set("User-Agent", "agent-a")
	if pipelineCheckSessionHijacking(ctx).(bool) {
		t.Fatal("existing fingerprint should be allowed")
	}
	c.Request().Header.Set("User-Agent", "agent-b")
	if !pipelineCheckSessionHijacking(ctx).(bool) {
		t.Fatal("new fingerprint exceeding concurrency should trigger hijacking detection")
	}
}

func TestAdvancedMITMCondition(t *testing.T) {
	app, c := acquireTestContext("GET", "/api/data")
	defer releaseTestContext(app, c)
	c.Request().Header.Set("User-Agent", "scanner-bot")
	c.Request().Header.Set("X-Forwarded-For", "203.0.113.10")
	collector := NewInMemoryMetricsCollector()
	re := &RuleEngine{
		metrics:         collector,
		detectionLedger: NewDetectionLedger(time.Minute),
	}
	ctx := &Context{
		RuleEngine: re,
		FiberCtx:   c,
		Results: map[string]any{
			"indicators":           []any{"suspicious_user_agent"},
			"suspiciousUserAgents": []any{"scanner"},
		},
	}
	if !AdvancedMITMCondition(ctx).(bool) {
		t.Fatal("expected suspicious user agent to trigger MITM detection")
	}
	labels := map[string]string{
		"indicator": "mitm_suspicious_user_agent",
		"severity":  "high",
	}
	if collector.GetCounterValue("mitm_detection_total", labels) == 0 {
		t.Fatal("expected metrics counter increment for MITM detection")
	}
	summary := re.detectionLedger.Summary()
	if summary.TotalFindings == 0 {
		t.Fatal("expected detection ledger to record MITM finding")
	}
}

func TestTelemetryStoreLifecycle(t *testing.T) {
	store := NewTelemetryStore(50 * time.Millisecond)
	metrics := map[string]float64{"syn_rate": 180, "half_open": 75}
	store.Ingest("10.1.1.1", metrics)
	snapshot := store.Snapshot("10.1.1.1")
	if snapshot == nil {
		t.Fatal("expected telemetry snapshot after ingest")
	}
	if snapshot["syn_rate"] != 180 {
		t.Fatalf("expected syn_rate to be 180, got %v", snapshot["syn_rate"])
	}
	time.Sleep(60 * time.Millisecond)
	if stale := store.Snapshot("10.1.1.1"); stale != nil {
		t.Fatal("expected telemetry snapshot to expire after TTL")
	}
}

func TestDetectionLedgerSummary(t *testing.T) {
	ledger := NewDetectionLedger(500 * time.Millisecond)
	ledger.Record(DetectionEvent{
		ClientIP: "1.2.3.4",
		Endpoint: "/api/a",
		Findings: []AttackFinding{{Name: "http_flood", Severity: "high"}},
	})
	ledger.Record(DetectionEvent{
		ClientIP: "5.6.7.8",
		Endpoint: "/api/b",
		Findings: []AttackFinding{{Name: "http_flood", Severity: "high"}, {Name: "slowloris", Severity: "medium"}},
	})
	summary := ledger.Summary()
	if summary.TotalFindings != 3 {
		t.Fatalf("expected 3 findings, got %d", summary.TotalFindings)
	}
	if summary.ActiveAttacks["http_flood"] != 2 {
		t.Fatalf("expected two http_flood findings, got %d", summary.ActiveAttacks["http_flood"])
	}
	if summary.ActiveIPs != 2 {
		t.Fatalf("expected two active IPs, got %d", summary.ActiveIPs)
	}
	time.Sleep(600 * time.Millisecond)
	summary = ledger.Summary()
	if summary.TotalFindings != 0 {
		t.Fatalf("expected findings to expire, got %d", summary.TotalFindings)
	}
}

func acquireTestContext(method, path string) (*fiber.App, *fiber.Ctx) {
	app := fiber.New()
	reqCtx := new(fasthttp.RequestCtx)
	reqCtx.Request.Header.SetMethod(method)
	reqCtx.Request.SetRequestURI(path)
	return app, app.AcquireCtx(reqCtx)
}

func releaseTestContext(app *fiber.App, c *fiber.Ctx) {
	if app != nil && c != nil {
		app.ReleaseCtx(c)
	}
}
