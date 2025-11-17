package runner

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/oarkflow/ip"

	"github.com/oarkflow/tcpguard"
)

// Options control how the example runner boots.
type Options struct {
	ConfigDir string
	Port      string
}

// Run boots the Fiber demo app with the provided configuration directory.
func Run(opts Options) error {
	ip.Init()

	configDir := opts.ConfigDir
	if configDir == "" {
		configDir = "configs"
	}

	port := opts.Port
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "3000"
	}

	store := tcpguard.NewInMemoryCounterStore()
	rateLimiter := tcpguard.NewTokenBucketRateLimiter(100, time.Minute)
	actionRegistry := tcpguard.NewActionHandlerRegistry()
	pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()
	metrics := tcpguard.NewInMemoryMetricsCollector()

	registerExamplePipelineFunctions(pipelineReg)

	ruleEngine, err := tcpguard.NewRuleEngine(
		configDir,
		store,
		rateLimiter,
		actionRegistry,
		pipelineReg,
		metrics,
		tcpguard.NewDefaultConfigValidator(),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize rule engine: %w", err)
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
		},
	})

	app.Use(cors.New())
	app.Use(ruleEngine.AnomalyDetectionMiddleware())
	app.Static("/static", "./static")
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("./static/index.html")
	})

	registerRoutes(app, store, metrics, rateLimiter, ruleEngine)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-shutdown
		log.Println("\nShutting down gracefully...")

		if err := ruleEngine.StopWatcher(); err != nil {
			log.Printf("error stopping file watcher: %v\n", err)
		}

		if err := app.Shutdown(); err != nil {
			log.Printf("error shutting down server: %v\n", err)
		}
	}()

	log.Printf("Starting TCPGuard example on :%s using %s\n", port, configDir)
	return app.Listen(":" + port)
}

func registerExamplePipelineFunctions(reg tcpguard.PipelineFunctionRegistry) {
	if reg == nil {
		return
	}

	register := func(name string, fn func(ctx *tcpguard.Context) any) {
		if name == "" || fn == nil {
			return
		}
		if _, exists := reg.Get(name); exists {
			return
		}
		reg.Register(name, fn)
	}

	register("checkRequestMethod", func(ctx *tcpguard.Context) any {
		method := ctx.FiberCtx.Method()
		expected, ok := ctx.Results["method"].(string)
		if !ok || expected == "" {
			return method
		}
		return method == expected
	})

	register("getCurrentTime", func(ctx *tcpguard.Context) any {
		return time.Now()
	})

	register("parseTime", func(ctx *tcpguard.Context) any {
		timeStr, ok := ctx.Results["timeString"].(string)
		if !ok {
			return nil
		}
		layout, ok := ctx.Results["layout"].(string)
		if !ok || layout == "" {
			layout = "15:04"
		}
		parsed, err := time.Parse(layout, timeStr)
		if err != nil {
			return nil
		}
		return parsed
	})

	register("checkBusinessHours", func(ctx *tcpguard.Context) any {
		endpoint := ctx.FiberCtx.Path()
		expected, ok := ctx.Results["endpoint"].(string)
		if !ok || (expected != "" && endpoint != expected) {
			return false
		}

		now := time.Now()
		timezone, ok := ctx.Results["timezone"].(string)
		if !ok || timezone == "" {
			timezone = "UTC"
		}
		loc, err := time.LoadLocation(timezone)
		if err != nil {
			return false
		}
		localNow := now.In(loc)

		startTimeResult, ok := ctx.Results["parse_start"]
		if !ok {
			return false
		}
		endTimeResult, ok := ctx.Results["parse_end"]
		if !ok {
			return false
		}

		startTime, ok := startTimeResult.(time.Time)
		if !ok {
			return false
		}
		endTime, ok := endTimeResult.(time.Time)
		if !ok {
			return false
		}

		startTime = time.Date(localNow.Year(), localNow.Month(), localNow.Day(), startTime.Hour(), startTime.Minute(), 0, 0, loc)
		endTime = time.Date(localNow.Year(), localNow.Month(), localNow.Day(), endTime.Hour(), endTime.Minute(), 0, 0, loc)

		return localNow.Before(startTime) || localNow.After(endTime)
	})

	register("getClientIP", func(ctx *tcpguard.Context) any {
		return ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	})

	register("getCountryFromIP", func(ctx *tcpguard.Context) any {
		clientIP, ok := ctx.Results["get_ip"].(string)
		if !ok {
			defaultCountry, ok := ctx.Results["defaultCountry"].(string)
			if !ok {
				defaultCountry = "US"
			}
			return defaultCountry
		}
		defaultCountry, ok := ctx.Results["defaultCountry"].(string)
		if !ok {
			defaultCountry = "US"
		}
		return ctx.RuleEngine.GetCountryFromIP(clientIP, defaultCountry)
	})

	register("checkBusinessRegion", func(ctx *tcpguard.Context) any {
		endpoint := ctx.FiberCtx.Path()
		expected, ok := ctx.Results["endpoint"].(string)
		if !ok || (expected != "" && endpoint != expected) {
			return false
		}
		country, ok := ctx.Results["get_country"].(string)
		if !ok {
			return false
		}
		allowedCountries, ok := ctx.Results["allowedCountries"].([]any)
		if !ok {
			return false
		}
		for _, a := range allowedCountries {
			if aStr, ok := a.(string); ok && aStr == country {
				return false
			}
		}
		return true
	})

	register("checkProtectedRoute", func(ctx *tcpguard.Context) any {
		endpoint := ctx.FiberCtx.Path()
		protectedRoutes, ok := ctx.Results["protectedRoutes"].([]any)
		if !ok {
			return false
		}
		protected := false
		for _, r := range protectedRoutes {
			if rStr, ok := r.(string); ok && strings.HasPrefix(endpoint, rStr) {
				protected = true
				break
			}
		}
		if !protected {
			return false
		}
		header, ok := ctx.Results["loginCheckHeader"].(string)
		if !ok || header == "" {
			header = "Authorization"
		}
		return ctx.FiberCtx.Get(header) == ""
	})

	register("checkSessionHijacking", func(ctx *tcpguard.Context) any {
		userID := ctx.RuleEngine.GetUserID(ctx.FiberCtx)
		if userID == "" {
			return false
		}
		userAgent := ctx.FiberCtx.Get("User-Agent")
		sessions, err := ctx.RuleEngine.Store.GetSessions(userID)
		if err != nil {
			return false
		}
		if sessions == nil {
			sessions = []*tcpguard.SessionInfo{}
		}
		now := time.Now()
		sessionTimeoutStr, ok := ctx.Results["sessionTimeout"].(string)
		if !ok || sessionTimeoutStr == "" {
			sessionTimeoutStr = "24h"
		}
		timeout, _ := time.ParseDuration(sessionTimeoutStr)
		validSessions := []*tcpguard.SessionInfo{}
		for _, s := range sessions {
			if now.Sub(s.Created) < timeout {
				validSessions = append(validSessions, s)
			}
		}
		found := false
		for _, s := range validSessions {
			if s.UA == userAgent {
				found = true
				break
			}
		}
		maxConcurrent, ok := ctx.Results["maxConcurrentSessions"].(float64)
		if !ok {
			maxConcurrent = 1
		}
		if !found {
			if len(validSessions) >= int(maxConcurrent) {
				return true
			}
			validSessions = append(validSessions, &tcpguard.SessionInfo{
				UA:      userAgent,
				Created: now,
			})
		}
		ctx.RuleEngine.Store.PutSessions(userID, validSessions)
		return false
	})

	register("ddos", tcpguard.AdvancedDDoSCondition)
	register("mitm", func(ctx *tcpguard.Context) any {
		c := ctx.FiberCtx
		userAgent := c.Get("User-Agent")

		indicatorsInterface, ok := ctx.Results["indicators"]
		if !ok {
			return false
		}
		indicatorsAny, ok := indicatorsInterface.([]any)
		if !ok {
			return false
		}
		var indicators []string
		for _, ind := range indicatorsAny {
			if str, ok := ind.(string); ok {
				indicators = append(indicators, str)
			}
		}
		if len(indicators) == 0 {
			return false
		}

		for _, indicator := range indicators {
			switch indicator {
			case "invalid_ssl_certificate":
				if c.Protocol() == "https" && false {
					return true
				}
			case "abnormal_tls_handshake":
				if false {
					return true
				}
			case "suspicious_user_agent":
				suspiciousAgentsInterface, ok := ctx.Results["suspiciousUserAgents"]
				if !ok {
					continue
				}
				suspiciousAgentsAny, ok := suspiciousAgentsInterface.([]any)
				if !ok {
					continue
				}
				var patterns []string
				for _, agent := range suspiciousAgentsAny {
					if str, ok := agent.(string); ok {
						patterns = append(patterns, str)
					}
				}
				if len(patterns) == 0 {
					continue
				}
				ua := strings.ToLower(userAgent)
				for _, pattern := range patterns {
					if strings.Contains(ua, strings.ToLower(pattern)) {
						return true
					}
				}
			case "unexpected_headers":
				headers := c.GetReqHeaders()
				for _, values := range headers {
					if len(values) > 10 {
						return true
					}
					for _, value := range values {
						if len(value) > 4096 {
							return true
						}
					}
				}
			case "anomalous_request_size":
				if c.Request().Header.ContentLength() > 10*1024*1024 {
					return true
				}
			}
		}
		return false
	})
}

func registerRoutes(app *fiber.App, store tcpguard.CounterStore, metrics tcpguard.MetricsCollector, rateLimiter tcpguard.RateLimiter, ruleEngine *tcpguard.RuleEngine) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("./static/index.html")
	})

	app.Post("/api/login", func(c *fiber.Ctx) error {
		var loginReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&loginReq); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		if loginReq.Username != "admin" || loginReq.Password != "password" {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		return c.JSON(fiber.Map{"message": "Login successful"})
	})

	app.Get("/api/data/export", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"data": []map[string]any{
				{"id": 1, "name": "Sample Data 1"},
				{"id": 2, "name": "Sample Data 2"},
			},
			"exported_at": time.Now().Format(time.RFC3339),
		})
	})

	app.Get("/api/protected", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is a protected endpoint",
			"user":    "authenticated_user",
		})
	})

	app.Get("/api/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		health := fiber.Map{
			"status":    "ok",
			"timestamp": time.Now().Format(time.RFC3339),
			"services":  fiber.Map{},
		}

		if err := store.HealthCheck(); err != nil {
			health["status"] = "degraded"
			health["services"].(fiber.Map)["store"] = fiber.Map{"status": "error", "error": err.Error()}
		} else {
			health["services"].(fiber.Map)["store"] = fiber.Map{"status": "ok"}
		}

		if err := metrics.HealthCheck(); err != nil {
			health["status"] = "degraded"
			health["services"].(fiber.Map)["metrics"] = fiber.Map{"status": "error", "error": err.Error()}
		} else {
			health["services"].(fiber.Map)["metrics"] = fiber.Map{"status": "ok"}
		}

		if err := rateLimiter.HealthCheck(); err != nil {
			health["status"] = "degraded"
			health["services"].(fiber.Map)["rate_limiter"] = fiber.Map{"status": "error", "error": err.Error()}
		} else {
			health["services"].(fiber.Map)["rate_limiter"] = fiber.Map{"status": "ok"}
		}

		if err := ruleEngine.HealthCheck(); err != nil {
			health["status"] = "degraded"
			health["services"].(fiber.Map)["rule_engine"] = fiber.Map{"status": "error", "error": err.Error()}
		} else {
			health["services"].(fiber.Map)["rule_engine"] = fiber.Map{"status": "ok"}
		}

		statusCode := 200
		if health["status"] == "degraded" {
			statusCode = 503
		}

		return c.Status(statusCode).JSON(health)
	})

	app.Get("/api/rules", func(c *fiber.Ctx) error {
		rules := ruleEngine.GetRules()
		return c.JSON(fiber.Map{"rules": rules})
	})

	app.Post("/api/rules/reload", func(c *fiber.Ctx) error {
		if err := ruleEngine.ReloadConfig(); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"message": "Configuration reloaded"})
	})

	app.Get("/api/test/:scenario", func(c *fiber.Ctx) error {
		scenario := c.Params("scenario")

		switch scenario {
		case "normal":
			return c.JSON(fiber.Map{"message": "Normal request processed", "status": "ok"})
		case "suspicious":
			return c.JSON(fiber.Map{"message": "Suspicious request detected", "status": "flagged"})
		case "business-hours":
			return c.JSON(fiber.Map{"message": "Business hours check", "status": "ok"})
		default:
			return c.Status(400).JSON(fiber.Map{"error": "Unknown test scenario"})
		}
	})

	app.Get("/api/admin", func(c *fiber.Ctx) error {
		auth := c.Get("Authorization")
		if auth == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Authorization required"})
		}
		return c.JSON(fiber.Map{"message": "Admin access granted", "user": "admin"})
	})
}
