package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/authz"
	"github.com/oarkflow/tcpguard"
)

const defaultConfigDir = "./config-data"
const defaultAddr = ":3000"

func main() {
	configDir := envOrDefault("TCPGUARD_CONFIG_DIR", defaultConfigDir)
	addr := envOrDefault("TCPGUARD_ADDR", defaultAddr)
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

	app, _, _, err := newApp(configDir, authSecret)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Config API authz demo: http://localhost%s", addr)
	log.Println(`Mint a token: TCPGUARD_AUTH_SECRET=... go run ./examples/config-api-authz token admin config_admin`)
	log.Println(`Use it: curl -i -H "Authorization: Bearer ${TOKEN}" http://localhost` + addr + `/api/rules`)
	log.Fatal(app.Listen(addr))
}

func printToken(secret []byte, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: go run ./examples/config-api-authz token <user> <comma-separated-roles> [comma-separated-groups]")
	}
	token, err := tcpguard.NewConfigAPISignedAuthToken(secret, tcpguard.ConfigAPIAuthIdentity{
		UserID:   args[0],
		Roles:    splitHeaderList(args[1]),
		Groups:   optionalList(args, 2),
		TenantID: "default",
	}, 15*time.Minute)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func newApp(configDir string, authSecret []byte) (*fiber.App, *tcpguard.FileConfigStore, *tcpguard.InMemoryEventEmitter, error) {
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
	authMiddleware, err := tcpguard.NewConfigAPISignedAuthMiddleware(authSecret)
	if err != nil {
		return nil, nil, nil, err
	}

	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "TCPGuard ConfigAPI authz demo"})
	})
	app.Use(authMiddleware)
	configAPI.RegisterRoutes(app)
	app.Get("/demo/whoami", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user":   c.Locals("tcpguard.user_id"),
			"roles":  c.Locals("tcpguard.user_roles"),
			"groups": c.Locals("tcpguard.user_groups"),
			"tenant": c.Locals("tcpguard.tenant_id"),
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

func optionalList(args []string, index int) []string {
	if len(args) <= index {
		return nil
	}
	return splitHeaderList(args[index])
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
