package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/oarkflow/tcpguard"
)

func main() {
	// Determine config directory
	configDir := "configs"
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	// Try multiple locations for config directory
	possiblePaths := []string{
		configDir,
		"./configs",
		"../configs",
		"./examples/configs",
		"configs",
	}

	var foundConfigDir string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			foundConfigDir = path
			break
		}
	}

	if foundConfigDir == "" {
		log.Fatal("Could not find configs directory in any of the expected locations")
	}

	// Initialize dependencies
	store := tcpguard.NewInMemoryCounterStore()
	rateLimiter := tcpguard.NewTokenBucketRateLimiter(100, time.Minute) // 100 requests per minute
	actionRegistry := tcpguard.NewActionHandlerRegistry()
	pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()
	// metrics := // placeholder for metrics

	// Register pipeline functions
	pipelineReg.Register("checkEndpoint", func(ctx *tcpguard.PipelineContext) any {
		endpoint := ctx.FiberCtx.Path()
		expected, ok := ctx.Results["endpoint"].(string)
		if !ok {
			return endpoint
		}
		return endpoint == expected
	})
	pipelineReg.Register("getCurrentTime", func(ctx *tcpguard.PipelineContext) any {
		return time.Now()
	})
	pipelineReg.Register("parseTime", func(ctx *tcpguard.PipelineContext) any {
		timeStr, ok := ctx.Results["timeString"].(string)
		if !ok {
			return nil
		}
		layout, ok := ctx.Results["layout"].(string)
		if !ok {
			layout = "15:04"
		}
		parsed, err := time.Parse(layout, timeStr)
		if err != nil {
			return nil
		}
		return parsed
	})
	pipelineReg.Register("checkBusinessHours", func(ctx *tcpguard.PipelineContext) any {
		endpoint := ctx.FiberCtx.Path()
		expected, ok := ctx.Results["endpoint"].(string)
		if !ok || endpoint != expected {
			return false
		}

		now := time.Now()
		timezone, ok := ctx.Results["timezone"].(string)
		if !ok {
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

		startTime = time.Date(localNow.Year(), localNow.Month(), localNow.Day(),
			startTime.Hour(), startTime.Minute(), 0, 0, loc)
		endTime = time.Date(localNow.Year(), localNow.Month(), localNow.Day(),
			endTime.Hour(), endTime.Minute(), 0, 0, loc)

		return localNow.Before(startTime) || localNow.After(endTime)
	})
	pipelineReg.Register("getClientIP", func(ctx *tcpguard.PipelineContext) any {
		return ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	})
	pipelineReg.Register("getCountryFromIP", func(ctx *tcpguard.PipelineContext) any {
		ip, ok := ctx.Results["get_ip"].(string)
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
		return ctx.RuleEngine.GetCountryFromIP(ip, defaultCountry)
	})
	pipelineReg.Register("checkBusinessRegion", func(ctx *tcpguard.PipelineContext) any {
		endpoint := ctx.FiberCtx.Path()
		expected, ok := ctx.Results["endpoint"].(string)
		if !ok || endpoint != expected {
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
	pipelineReg.Register("checkProtectedRoute", func(ctx *tcpguard.PipelineContext) any {
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
		if !ok {
			header = "Authorization"
		}
		return ctx.FiberCtx.Get(header) == ""
	})
	pipelineReg.Register("checkSessionHijacking", func(ctx *tcpguard.PipelineContext) any {
		userID := ctx.RuleEngine.GetUserID(ctx.FiberCtx)
		if userID == "" {
			return false
		}
		userAgent := string([]byte(ctx.FiberCtx.Get("User-Agent")))
		sessions, err := ctx.RuleEngine.Store.GetSessions(userID)
		if err != nil {
			return false
		}
		if sessions == nil {
			sessions = []*tcpguard.SessionInfo{}
		}
		now := time.Now()
		sessionTimeoutStr, ok := ctx.Results["sessionTimeout"].(string)
		if !ok {
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
	pipelineReg.Register("logicalAnd", func(ctx *tcpguard.PipelineContext) any {
		inputs, ok := ctx.Results["inputs"].([]any)
		if !ok {
			return false
		}
		for _, input := range inputs {
			if b, ok := input.(bool); ok && !b {
				return false
			}
		}
		return true
	})
	pipelineReg.Register("logicalOr", func(ctx *tcpguard.PipelineContext) any {
		inputs, ok := ctx.Results["inputs"].([]any)
		if !ok {
			return false
		}
		for _, input := range inputs {
			if b, ok := input.(bool); ok && b {
				return true
			}
		}
		return false
	})

	// Register global rule handlers
	pipelineReg.Register("ddos", func(ctx *tcpguard.PipelineContext) any {
		clientIP := ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
		count, lastReset, err := ctx.RuleEngine.Store.IncrementGlobal(clientIP)
		if err != nil {
			return false
		}
		now := time.Now()
		if now.Sub(lastReset) > time.Minute {
			ctx.RuleEngine.Store.ResetGlobal(clientIP)
			return false
		}
		threshold := 100
		if t, ok := ctx.Results["requestsPerMinute"].(float64); ok {
			threshold = int(t)
		}
		if threshold <= 0 {
			return false
		}
		return count > threshold
	})

	pipelineReg.Register("mitm", func(ctx *tcpguard.PipelineContext) any {
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
				// Check for invalid SSL certificate
				if false { // placeholder - implement SSL certificate validation
					return true
				}
			case "abnormal_tls_handshake":
				// Check for abnormal TLS handshake
				if false { // placeholder - implement TLS handshake analysis
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
			}
		}
		return false
	})

	// Initialize rule engine
	ruleEngine, err := tcpguard.NewRuleEngine(foundConfigDir, store, rateLimiter, actionRegistry, pipelineReg, nil)
	if err != nil {
		log.Fatal("Failed to initialize rule engine:", err)
	}

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Middleware
	app.Use(cors.New())
	app.Use(ruleEngine.AnomalyDetectionMiddleware())

	// Setup routes
	setupRoutes(app)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf(" Server starting on port %s\n", port)
	log.Printf(" Configuration loaded from %s\n", foundConfigDir)
	log.Printf(" Anomaly detection engine active\n")

	log.Fatal(app.Listen(":" + port))
}

// API endpoints for demonstration
func setupRoutes(app *fiber.App) {
	// Login endpoint
	app.Post("/api/login", func(c *fiber.Ctx) error {
		// Simulate login logic
		var loginReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&loginReq); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Simulate failed login for demo
		if loginReq.Username != "admin" || loginReq.Password != "password" {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		return c.JSON(fiber.Map{"message": "Login successful"})
	})

	// Data export endpoint
	app.Get("/api/data/export", func(c *fiber.Ctx) error {
		// Simulate data export
		return c.JSON(fiber.Map{
			"data": []map[string]interface{}{
				{"id": 1, "name": "Sample Data 1"},
				{"id": 2, "name": "Sample Data 2"},
			},
			"exported_at": time.Now().Format(time.RFC3339),
		})
	})

	// Protected endpoint
	app.Get("/api/protected", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is a protected endpoint",
			"user":    "authenticated_user",
		})
	})

	// Status endpoint
	app.Get("/api/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
}
