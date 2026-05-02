package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/authz"
	"github.com/oarkflow/tcpguard"
)

const (
	defaultAddr       = ":3000"
	defaultDBPath     = "./tcpguard-production.db"
	defaultCSRFTok    = "replace-this-csrf-token"
	defaultProxyCIDRs = "127.0.0.1/32,::1/128"
)

type appBundle struct {
	app         *fiber.App
	db          *sqlx.DB
	configStore *tcpguard.SQLConfigStore
	stateStore  *tcpguard.SQLStateStore
	emitter     *tcpguard.SQLEventEmitter
	configAPI   *tcpguard.ConfigAPI
}

func main() {
	authSecret := []byte(os.Getenv("TCPGUARD_AUTH_SECRET"))
	if len(os.Args) > 1 && os.Args[1] == "token" {
		if err := printToken(authSecret, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(authSecret) < 32 {
		log.Fatal("TCPGUARD_AUTH_SECRET must be set to at least 32 bytes")
	}

	bundle, err := newProductionApp(productionSettings{
		DBPath:            envOrDefault("TCPGUARD_DB", defaultDBPath),
		AuthSecret:        authSecret,
		CSRFToken:         envOrDefault("TCPGUARD_CSRF_TOKEN", defaultCSRFTok),
		TrustedProxyCIDRs: splitList(envOrDefault("TCPGUARD_TRUSTED_PROXY_CIDRS", defaultProxyCIDRs)),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer bundle.db.Close()

	addr := envOrDefault("TCPGUARD_ADDR", defaultAddr)
	log.Printf("TCPGuard production-ready example listening on http://127.0.0.1%s", addr)
	log.Println("TLS is expected at nginx/proxy; this app validates the backend TCPGuard controls.")
	log.Fatal(bundle.app.Listen(addr))
}

type productionSettings struct {
	DBPath            string
	AuthSecret        []byte
	CSRFToken         string
	TrustedProxyCIDRs []string
}

func newProductionApp(settings productionSettings) (*appBundle, error) {
	if len(settings.AuthSecret) < 32 {
		return nil, fmt.Errorf("auth secret must be at least 32 bytes")
	}
	if settings.CSRFToken == "" {
		return nil, fmt.Errorf("CSRF token is required")
	}
	if len(settings.TrustedProxyCIDRs) == 0 {
		return nil, fmt.Errorf("trusted proxy CIDRs are required")
	}

	dbPath := settings.DBPath
	if !strings.Contains(dbPath, "?") {
		dbPath += "?_busy_timeout=5000&_foreign_keys=on"
	}
	db, err := sqlx.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			db.Close()
		}
	}()

	configStore, err := tcpguard.NewSQLConfigStore(db)
	if err != nil {
		return nil, err
	}
	stateStore, err := tcpguard.NewSQLStateStore(db)
	if err != nil {
		return nil, err
	}
	emitter, err := tcpguard.NewSQLEventEmitter(db)
	if err != nil {
		return nil, err
	}
	if err := seedConfig(configStore); err != nil {
		return nil, err
	}

	authzEngine := tcpguard.NewDefaultConfigAPIAuthzEngine()
	if err := seedAuthz(authzEngine); err != nil {
		return nil, err
	}
	configAPI := tcpguard.NewConfigAPI(
		configStore,
		tcpguard.WithConfigAPIAuthz(authzEngine, tcpguard.DefaultConfigAPIAuthzResolver),
		tcpguard.WithConfigAPIValidator(tcpguard.NewDefaultConfigValidator()),
		tcpguard.WithConfigAPIEventEmitter(emitter),
		tcpguard.WithConfigAPIMutationRateLimit(60, time.Minute),
		tcpguard.WithConfigAPICSRFToken("X-CSRF-Token", settings.CSRFToken),
		tcpguard.WithConfigAPITrustedProxyCIDRs(settings.TrustedProxyCIDRs...),
	)

	if err := tcpguard.MustBeProductionReady(tcpguard.ProductionReadinessConfig{
		Mode:                 tcpguard.DeploymentProduction,
		ConfigAPI:            configAPI,
		ConfigAPIAuthSecret:  settings.AuthSecret,
		BehindTrustedProxy:   true,
		TrustedProxyCIDRs:    settings.TrustedProxyCIDRs,
		CounterStore:         stateStore,
		StateStore:           stateStore,
		EventEmitter:         emitter,
		RequireDurableState:  true,
		RequireAuditEmitter:  true,
		RequireConfigVersion: true,
		RequireSignedAuth:    true,
	}); err != nil {
		return nil, err
	}

	cfg, err := configStore.LoadAll()
	if err != nil {
		return nil, err
	}
	ruleEngine, err := tcpguard.NewRuleEngineWithConfig(
		cfg,
		stateStore,
		tcpguard.NewTokenBucketRateLimiterWithMax(1000, time.Minute, 50000),
		tcpguard.NewActionHandlerRegistry(),
		tcpguard.NewInMemoryPipelineFunctionRegistry(),
		tcpguard.NewInMemoryMetricsCollector(),
		tcpguard.NewDefaultConfigValidator(),
	)
	if err != nil {
		return nil, err
	}
	ruleEngine.ApplyOptions(tcpguard.WithStateStore(stateStore), tcpguard.WithEventEmitter(emitter))

	authMiddleware, err := tcpguard.NewConfigAPISignedAuthMiddleware(settings.AuthSecret)
	if err != nil {
		return nil, err
	}

	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"service": "tcpguard-production-ready", "status": "ok"})
	})
	app.Get("/ready", func(c fiber.Ctx) error {
		report := tcpguard.CheckProductionReadiness(tcpguard.ProductionReadinessConfig{
			Mode:                 tcpguard.DeploymentProduction,
			ConfigAPI:            configAPI,
			ConfigAPIAuthSecret:  settings.AuthSecret,
			BehindTrustedProxy:   true,
			TrustedProxyCIDRs:    settings.TrustedProxyCIDRs,
			CounterStore:         stateStore,
			StateStore:           stateStore,
			EventEmitter:         emitter,
			RequireDurableState:  true,
			RequireAuditEmitter:  true,
			RequireConfigVersion: true,
			RequireSignedAuth:    true,
		})
		if !report.Ready {
			return c.Status(503).JSON(report)
		}
		return c.JSON(report)
	})
	app.Use("/api", authMiddleware)
	configAPI.RegisterRoutes(app)
	app.Get("/api/audit", func(c fiber.Ctx) error {
		events, err := emitter.Query(context.Background(), tcpguard.EventFilter{Limit: 50})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(events)
	})
	app.Get("/app/ping", ruleEngine.AnomalyDetectionMiddleware(), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	cleanupOnError = false
	return &appBundle{
		app:         app,
		db:          db,
		configStore: configStore,
		stateStore:  stateStore,
		emitter:     emitter,
		configAPI:   configAPI,
	}, nil
}

func printToken(secret []byte, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: go run ./examples/production-ready token <user> <comma-separated-roles> [comma-separated-groups]")
	}
	token, err := tcpguard.NewConfigAPISignedAuthToken(secret, tcpguard.ConfigAPIAuthIdentity{
		UserID:   args[0],
		Roles:    splitList(args[1]),
		Groups:   optionalList(args, 2),
		TenantID: "default",
	}, 15*time.Minute)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

func seedConfig(store *tcpguard.SQLConfigStore) error {
	if global, err := store.GetGlobalConfig(); err == nil && global != nil {
		global.TrustProxy = true
		global.TrustedProxyCIDRs = []string{"127.0.0.1/32", "::1/128"}
		if global.Rules == nil {
			global.Rules = make(map[string]tcpguard.Rule)
		}
		if err := store.UpdateGlobalConfig(global); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	if rule, err := store.GetRule("baseline-ddos"); err != nil {
		return err
	} else if rule == nil {
		return store.CreateRule(&tcpguard.Rule{
			Name:     "baseline-ddos",
			Type:     "ddos",
			Enabled:  true,
			Priority: 10,
			Actions: []tcpguard.Action{{
				Type:     "temporary_ban",
				Duration: "10m",
				Response: tcpguard.Response{Status: 403, Message: "blocked"},
			}},
		})
	}
	return nil
}

func seedAuthz(engine *authz.Engine) error {
	ctx := context.Background()
	for subject, role := range map[string]string{
		"viewer": tcpguard.ConfigRoleViewer,
		"editor": tcpguard.ConfigRoleEditor,
		"admin":  tcpguard.ConfigRoleAdmin,
	} {
		if err := engine.AssignRoleToUser(ctx, subject, role); err != nil {
			return err
		}
	}
	return engine.GrantACL(ctx, &authz.ACL{
		ID:         "deny-editor-global-config",
		TenantID:   "default",
		ResourceID: "*",
		SubjectID:  "editor",
		Actions:    []authz.Action{"delete"},
		Effect:     authz.EffectDeny,
	})
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func optionalList(args []string, index int) []string {
	if len(args) <= index {
		return nil
	}
	return splitList(args[index])
}
