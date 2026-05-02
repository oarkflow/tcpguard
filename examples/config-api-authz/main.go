package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/authz"
	"github.com/oarkflow/tcpguard"
)

const defaultConfigDir = "./config-data"
const defaultAddr = ":3000"

func main() {
	configDir := envOrDefault("TCPGUARD_CONFIG_DIR", defaultConfigDir)
	addr := envOrDefault("TCPGUARD_ADDR", defaultAddr)

	app, _, _, err := newApp(configDir)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Config API authz demo: http://localhost%s", addr)
	log.Println(`Viewer can read:  curl -i -H "X-Demo-User: viewer" -H "X-Demo-Roles: config_viewer" http://localhost` + addr + `/api/rules`)
	log.Println(`Editor can write: curl -i -X POST -H "Content-Type: application/json" -H "X-Demo-User: editor" -H "X-Demo-Roles: config_editor" --data '{"name":"demoCreate","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}' http://localhost` + addr + `/api/rules`)
	log.Println(`Admin manages authz: curl -i -H "X-Demo-User: admin" -H "X-Demo-Roles: config_admin" http://localhost` + addr + `/api/authz/roles`)
	log.Fatal(app.Listen(addr))
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func newApp(configDir string) (*fiber.App, *tcpguard.FileConfigStore, *tcpguard.InMemoryEventEmitter, error) {
	if err := ensureConfigDirs(configDir); err != nil {
		return nil, nil, nil, err
	}
	configStore, err := tcpguard.NewFileConfigStore(configDir)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := seedConfig(configStore); err != nil {
		return nil, nil, nil, err
	}

	engine := tcpguard.NewDefaultConfigAPIAuthzEngine()
	if err := seedAuthz(engine); err != nil {
		return nil, nil, nil, err
	}
	emitter := tcpguard.NewInMemoryEventEmitter(100)
	configAPI := tcpguard.NewConfigAPI(
		configStore,
		tcpguard.WithConfigAPIAuthz(engine, tcpguard.DefaultConfigAPIAuthzResolver),
		tcpguard.WithConfigAPIValidator(tcpguard.NewDefaultConfigValidator()),
		tcpguard.WithConfigAPIEventEmitter(emitter),
	)

	app := fiber.New()
	app.Use(demoIdentityMiddleware)
	configAPI.RegisterRoutes(app)
	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "TCPGuard ConfigAPI authz demo",
			"users": fiber.Map{
				"viewer": "config_viewer can list/read config",
				"editor": "config_editor can mutate rules and endpoints",
				"admin":  "config_admin can manage config and authz",
			},
		})
	})
	app.Get("/demo/audit", func(c fiber.Ctx) error {
		events, err := emitter.Query(context.Background(), tcpguard.EventFilter{Limit: 20})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(events)
	})
	return app, configStore, emitter, nil
}

func demoIdentityMiddleware(c fiber.Ctx) error {
	userID := c.Get("X-Demo-User")
	if userID == "" {
		userID = c.Get("X-User-ID")
	}
	roles := c.Get("X-Demo-Roles")
	if roles == "" {
		roles = c.Get("X-User-Roles")
	}
	groups := c.Get("X-Demo-Groups")
	if groups == "" {
		groups = c.Get("X-User-Groups")
	}
	if userID != "" {
		c.Locals("tcpguard.user_id", userID)
	}
	if roles != "" {
		c.Locals("tcpguard.user_roles", splitHeaderList(roles))
	}
	if groups != "" {
		c.Locals("tcpguard.user_groups", splitHeaderList(groups))
	}
	c.Locals("tcpguard.tenant_id", "default")
	return c.Next()
}

func splitHeaderList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func ensureConfigDirs(configDir string) error {
	for _, dir := range []string{"rules", "endpoints", "global"} {
		if err := os.MkdirAll(filepath.Join(configDir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func seedConfig(store *tcpguard.FileConfigStore) error {
	if _, err := store.GetRule("blockedRule"); err != nil {
		return err
	}
	if err := store.CreateRule(&tcpguard.Rule{
		Name:    "blockedRule",
		Type:    "ddos",
		Enabled: true,
		Actions: []tcpguard.Action{{
			Type:     "temporary_ban",
			Duration: "10m",
			Response: tcpguard.Response{Status: 403, Message: "blocked"},
		}},
	}); err != nil {
		return err
	}
	return store.UpdateGlobalConfig(&tcpguard.GlobalRules{
		Rules:             make(map[string]tcpguard.Rule),
		AllowCIDRs:        []string{},
		DenyCIDRs:         []string{},
		TrustProxy:        false,
		TrustedProxyCIDRs: []string{},
	})
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
		ID:         "deny-editor-blocked-rule",
		TenantID:   "default",
		ResourceID: "blockedRule",
		SubjectID:  "editor",
		Actions:    []authz.Action{"update"},
		Effect:     authz.EffectDeny,
	})
}
