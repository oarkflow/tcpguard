// Package main demonstrates all three security detectors (injection, breach, anomaly)
// with test endpoints and curl commands.
//
// Run:
//
//	cd examples/security-detectors && go run .
//
// The server loads injection, breach, and anomaly configs from ../configs/global/
// and provides test endpoints to exercise each detector.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/ip"
	"github.com/oarkflow/tcpguard"
)

func main() {
	ip.Init()
	port := os.Getenv("PORT")
	if port == "" {
		port = "4001"
	}

	store := tcpguard.NewInMemoryCounterStore()
	rateLimiter := tcpguard.NewTokenBucketRateLimiter(200, time.Minute)
	actionRegistry := tcpguard.NewActionHandlerRegistry()
	pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()
	metrics := tcpguard.NewInMemoryMetricsCollector()

	ruleEngine, err := tcpguard.NewRuleEngine(
		"../configs",
		store,
		rateLimiter,
		actionRegistry,
		pipelineReg,
		metrics,
		tcpguard.NewDefaultConfigValidator(),
	)
	if err != nil {
		log.Fatalf("Failed to create rule engine: %v", err)
	}

	app := fiber.New(fiber.Config{
		BodyLimit: 1024 * 1024,
		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
		},
	})

	// Health check (bypasses security middleware)
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "time": time.Now().Format(time.RFC3339)})
	})

	// Apply security middleware
	app.Use(ruleEngine.AnomalyDetectionMiddleware())

	// --- Normal endpoints for baseline building ---
	app.Get("/api/data", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Normal data response", "items": 10})
	})

	app.Get("/api/users", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"users": []string{"alice", "bob", "charlie"}})
	})

	app.Post("/api/login", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Login endpoint", "status": "ok"})
	})

	app.Get("/api/search", func(c fiber.Ctx) error {
		q := c.Query("q", "")
		return c.JSON(fiber.Map{"query": q, "results": []string{}})
	})

	app.Post("/api/submit", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Form submitted", "status": "ok"})
	})

	app.Get("/admin", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Admin panel", "tier": "restricted"})
	})

	app.Get("/api/export/data", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Data export endpoint", "records": 5000})
	})

	// Show loaded rules
	app.Get("/api/rules", func(c fiber.Ctx) error {
		return c.JSON(ruleEngine.GetRules())
	})

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdown
		log.Println("\nShutting down...")
		_ = ruleEngine.StopWatcher()
		_ = app.Shutdown()
	}()

	printBanner(port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}

func printBanner(port string) {
	banner := `
=====================================================================
  TCPGuard Security Detectors Demo
  Injection (192+ patterns) | Breach (6 detectors) | Anomaly (7 detectors)
=====================================================================`
	fmt.Println(banner)

	tests := map[string][]map[string]string{
		"1. Injection Detection": {
			{"name": "SQL Injection (query param)", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/search?q=admin'+OR+1=1--"`, port)},
			{"name": "XSS (query param)", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/search?q=<script>alert('xss')</script>"`, port)},
			{"name": "Command Injection (body)", "cmd": fmt.Sprintf(`curl -s -X POST http://localhost:%s/api/submit -H "Content-Type: text/plain" -d "test; cat /etc/passwd"`, port)},
			{"name": "Path Traversal", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/search?file=../../etc/passwd"`, port)},
			{"name": "NoSQL Injection (body)", "cmd": fmt.Sprintf(`curl -s -X POST http://localhost:%s/api/submit -H "Content-Type: application/json" -d '{"user":{"$ne":""},"pass":{"$ne":""}}'`, port)},
			{"name": "Template Injection", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/search?q={{7*7}}"`, port)},
			{"name": "Clean request (should pass)", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/search?q=hello+world"`, port)},
		},
		"2. Breach Detection": {
			{"name": "Normal login", "cmd": fmt.Sprintf(`curl -s -X POST http://localhost:%s/api/login -H "X-User-ID: alice"`, port)},
			{"name": "Bulk data access", "cmd": fmt.Sprintf(`for i in $(seq 1 5); do curl -s "http://localhost:%s/api/export/data" -H "X-User-ID: alice"; done`, port)},
			{"name": "Admin probing", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/admin" -H "X-User-ID: bob"`, port)},
		},
		"3. Anomaly Detection": {
			{"name": "Build baseline (run 15x)", "cmd": fmt.Sprintf(`for i in $(seq 1 15); do curl -s "http://localhost:%s/api/data" > /dev/null; done && echo "baseline built"`, port)},
			{"name": "Normal request", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/data"`, port)},
		},
		"4. Verify Rules Loaded": {
			{"name": "Show active rules", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/api/rules" | python3 -m json.tool`, port)},
			{"name": "Health check", "cmd": fmt.Sprintf(`curl -s "http://localhost:%s/health"`, port)},
		},
	}

	b, _ := json.MarshalIndent(tests, "", "  ")
	fmt.Printf("\n  Listening on :%s\n\n  Test commands:\n%s\n\n", port, string(b))
}
