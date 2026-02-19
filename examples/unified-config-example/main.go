package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/tcpguard"
)

func main() {
	store := tcpguard.NewInMemoryCounterStore()
	rateLimiter := tcpguard.NewTokenBucketRateLimiter(100, time.Minute)
	metrics := tcpguard.NewInMemoryMetricsCollector()
	actionRegistry := tcpguard.NewActionHandlerRegistry()
	pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()

	// File-based config store
	configStore, err := tcpguard.NewFileConfigStore("../configs")
	
	// SQL alternative:
	// db, _ := sqlx.Connect("sqlite3", "./tcpguard.db")
	// configStore, err := tcpguard.NewSQLConfigStore(db)
	
	if err != nil {
		log.Fatal(err)
	}

	config, _ := configStore.LoadAll()

	ruleEngine, err := tcpguard.NewRuleEngineWithConfig(
		config, store, rateLimiter, actionRegistry,
		pipelineReg, metrics, tcpguard.NewDefaultConfigValidator(),
	)
	if err != nil {
		log.Fatal(err)
	}

	ugMiddleware := tcpguard.NewUserGroupMiddleware(ruleEngine, configStore)
	configAPI := tcpguard.NewConfigAPI(configStore)

	app := fiber.New()
	configAPI.RegisterRoutes(app)
	app.Use(ugMiddleware.Middleware())

	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "TCPGuard Unified Config"})
	})

	log.Fatal(app.Listen(":3000"))
}
