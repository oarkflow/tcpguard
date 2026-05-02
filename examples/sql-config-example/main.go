package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/tcpguard"
)

func main() {
	db, err := sqlx.Connect("sqlite3", "./tcpguard.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	configStore, err := tcpguard.NewSQLConfigStore(db)
	if err != nil {
		log.Fatal(err)
	}

	if err := seedDatabase(configStore); err != nil {
		log.Fatal(err)
	}

	store := tcpguard.NewInMemoryCounterStore()
	rateLimiter := tcpguard.NewTokenBucketRateLimiter(100, time.Minute)
	metrics := tcpguard.NewInMemoryMetricsCollector()
	actionRegistry := tcpguard.NewActionHandlerRegistry()
	pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()

	config, err := configStore.LoadAll()
	if err != nil {
		log.Fatal(err)
	}

	ruleEngine, err := tcpguard.NewRuleEngineWithConfig(
		config, store, rateLimiter, actionRegistry,
		pipelineReg, metrics, tcpguard.NewDefaultConfigValidator(),
	)
	if err != nil {
		log.Fatal(err)
	}

	ugMiddleware := tcpguard.NewUserGroupMiddleware(ruleEngine, configStore)
	authzEngine := tcpguard.NewDefaultConfigAPIAuthzEngine()
	configAPI := tcpguard.NewConfigAPI(
		configStore,
		tcpguard.WithConfigAPIAuthz(authzEngine, tcpguard.HeaderConfigAPIAuthzResolver),
		tcpguard.WithConfigAPIValidator(tcpguard.NewDefaultConfigValidator()),
	)

	app := fiber.New()
	app.Get("/static/*", static.New("./static"))
	configAPI.RegisterRoutes(app)

	app.Use(ugMiddleware.Middleware())
	app.Use(ruleEngine.AnomalyDetectionMiddleware())

	app.Get("/", func(c fiber.Ctx) error {
		return c.SendFile("./static/index.html")
	})

	app.Get("/admin/dashboard", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Admin dashboard"})
	})

	app.Post("/api/login", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Login successful"})
	})

	log.Println("Server: http://localhost:3000")
	log.Println(`Config API demo auth: add -H "X-User-ID: admin" -H "X-User-Roles: config_admin"`)
	log.Fatal(app.Listen(":3000"))
}

func seedDatabase(store *tcpguard.SQLConfigStore) error {
	groups := []*tcpguard.Group{
		{ID: "admin-group", Name: "Administrators", Description: "Full access"},
		{ID: "dev-group", Name: "Developers", Description: "Development team"},
		{ID: "viewer-group", Name: "Viewers", Description: "Read-only"},
	}
	for _, g := range groups {
		store.CreateGroup(g)
	}

	users := []*tcpguard.User{
		{ID: "user-1", Username: "admin", Email: "admin@example.com", Groups: []string{"admin-group"}},
		{ID: "user-2", Username: "developer", Email: "dev@example.com", Groups: []string{"dev-group"}},
		{ID: "user-3", Username: "viewer", Email: "viewer@example.com", Groups: []string{"viewer-group"}},
	}
	for _, u := range users {
		store.CreateUser(u)
	}

	store.UpdateGlobalConfig(&tcpguard.GlobalRules{
		Rules:             make(map[string]tcpguard.Rule),
		AllowCIDRs:        []string{},
		DenyCIDRs:         []string{},
		TrustProxy:        false,
		TrustedProxyCIDRs: []string{},
	})

	store.CreateRule(&tcpguard.Rule{
		Name:     "ddosDetection",
		Type:     "ddos",
		Enabled:  true,
		Priority: 100,
		Params:   map[string]any{"requestsPerMinute": 50},
		Actions: []tcpguard.Action{
			{
				Type:     "temporary_ban",
				Priority: 10,
				Duration: "10m",
				Response: tcpguard.Response{Status: 403, Message: "Temporary ban due to suspected DDoS activity."},
			},
		},
	})

	store.CreateRule(&tcpguard.Rule{
		Name:     "strictDDoSForViewers",
		Type:     "ddos",
		Enabled:  true,
		Priority: 100,
		Users:    []string{"user-3"},
		Groups:   []string{"viewer-group"},
		Params:   map[string]any{"requestsPerMinute": 20},
		Actions: []tcpguard.Action{
			{
				Type:     "temporary_ban",
				Priority: 10,
				Duration: "5m",
				Response: tcpguard.Response{Status: 403, Message: "Strict rate limit for viewers."},
			},
		},
	})

	store.CreateEndpoint(&tcpguard.EndpointRules{
		Name:      "login",
		Endpoint:  "/api/login",
		RateLimit: tcpguard.RateLimit{RequestsPerMinute: 5, Burst: 2},
		Actions: []tcpguard.Action{
			{
				Type:     "rate_limit",
				Response: tcpguard.Response{Status: 429, Message: "Too many login attempts."},
			},
		},
	})

	log.Println("Database seeded")
	return nil
}
