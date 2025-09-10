package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"

	"github.com/example/tcpguard"
)

func main() {
	// Create config file if it doesn't exist
	configPath := "config.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic(err)
	}

	// Initialize rule engine
	ruleEngine, err := tcpguard.NewRuleEngine(configPath)
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
	app.Use(logger.New())
	app.Use(cors.New())
	app.Use(ruleEngine.AnomalyDetectionMiddleware())

	// Setup routes
	setupRoutes(app)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("📋 Configuration loaded from %s", configPath)
	log.Printf("🛡️  Anomaly detection engine active")

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
