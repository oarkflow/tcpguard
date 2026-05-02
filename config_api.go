package tcpguard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/authz"
)

// ConfigAPIOperation describes the route access being authorized/audited.
type ConfigAPIOperation struct {
	Resource string
	Action   string
	Target   string
}

// ConfigAPIAuthorizer decides whether a request may access a config route.
type ConfigAPIAuthorizer func(c fiber.Ctx, op ConfigAPIOperation) bool

// ConfigAPIOption configures the runtime configuration API.
type ConfigAPIOption func(*ConfigAPI)

type ConfigAPI struct {
	store              ConfigStore
	validator          ConfigValidator
	eventEmitter       EventEmitter
	authorizer         ConfigAPIAuthorizer
	authzEngine        *authz.Engine
	authzResolver      ConfigAPIAuthzResolver
	unsafePublicAccess bool
	version            int
}

func NewConfigAPI(store ConfigStore, opts ...ConfigAPIOption) *ConfigAPI {
	api := &ConfigAPI{store: store, version: 1}
	if versioned, ok := store.(VersionedConfigStore); ok {
		if version, err := versioned.GetConfigVersion(); err == nil && version > 0 {
			api.version = version
		}
	}
	for _, opt := range opts {
		opt(api)
	}
	return api
}

// WithConfigAPIAdminToken enables bearer-token authorization for config routes.
func WithConfigAPIAdminToken(token string) ConfigAPIOption {
	return func(api *ConfigAPI) {
		api.authorizer = func(c fiber.Ctx, _ ConfigAPIOperation) bool {
			const prefix = "Bearer "
			header := c.Get("Authorization")
			if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
				return false
			}
			got := header[len(prefix):]
			return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
		}
	}
}

// WithConfigAPIAuthorizer installs a custom authorization hook.
func WithConfigAPIAuthorizer(authorizer ConfigAPIAuthorizer) ConfigAPIOption {
	return func(api *ConfigAPI) {
		api.authorizer = authorizer
	}
}

// WithConfigAPIAuthz enables RBAC/ABAC/ACL checks using github.com/oarkflow/authz.
func WithConfigAPIAuthz(engine *authz.Engine, resolver ConfigAPIAuthzResolver) ConfigAPIOption {
	return func(api *ConfigAPI) {
		api.authzEngine = engine
		if resolver == nil {
			resolver = DefaultConfigAPIAuthzResolver
		}
		api.authzResolver = resolver
	}
}

// WithConfigAPIValidator validates config mutations before they are committed.
func WithConfigAPIValidator(validator ConfigValidator) ConfigAPIOption {
	return func(api *ConfigAPI) {
		api.validator = validator
	}
}

// WithConfigAPIEventEmitter emits audit events for config reads and mutations.
func WithConfigAPIEventEmitter(emitter EventEmitter) ConfigAPIOption {
	return func(api *ConfigAPI) {
		api.eventEmitter = emitter
	}
}

// WithConfigAPIUnsafePublicAccess restores the historical unauthenticated API.
// It should be used only for local examples, tests, or trusted private tooling.
func WithConfigAPIUnsafePublicAccess() ConfigAPIOption {
	return func(api *ConfigAPI) {
		api.unsafePublicAccess = true
	}
}

func (api *ConfigAPI) RegisterRoutes(app *fiber.App) {
	// Rules
	app.Get("/api/rules", api.ListRules)
	app.Get("/api/rules/:name", api.GetRule)
	app.Post("/api/rules", api.CreateRule)
	app.Put("/api/rules/:name", api.UpdateRule)
	app.Delete("/api/rules/:name", api.DeleteRule)

	// Endpoints
	app.Get("/api/endpoints", api.ListEndpoints)
	app.Get("/api/endpoints/:endpoint", api.GetEndpoint)
	app.Post("/api/endpoints", api.CreateEndpoint)
	app.Put("/api/endpoints/:endpoint", api.UpdateEndpoint)
	app.Delete("/api/endpoints/:endpoint", api.DeleteEndpoint)

	// Global config
	app.Get("/api/config/global", api.GetGlobalConfig)
	app.Put("/api/config/global", api.UpdateGlobalConfig)

	// Users
	app.Get("/api/users", api.ListUsers)
	app.Get("/api/users/:id", api.GetUser)
	app.Post("/api/users", api.CreateUser)
	app.Put("/api/users/:id", api.UpdateUser)
	app.Delete("/api/users/:id", api.DeleteUser)

	// Groups
	app.Get("/api/groups", api.ListGroups)
	app.Get("/api/groups/:id", api.GetGroup)
	app.Post("/api/groups", api.CreateGroup)
	app.Put("/api/groups/:id", api.UpdateGroup)
	app.Delete("/api/groups/:id", api.DeleteGroup)

	// User-Group associations
	app.Post("/api/users/:userId/groups/:groupId", api.AddUserToGroup)
	app.Delete("/api/users/:userId/groups/:groupId", api.RemoveUserFromGroup)
	app.Get("/api/users/:userId/groups", api.GetUserGroups)
	app.Get("/api/groups/:groupId/users", api.GetGroupUsers)

	// Authz management. These routes are guarded by the same ConfigAPI authz path.
	app.Get("/api/authz/roles", api.ListAuthzRoles)
	app.Get("/api/authz/roles/:id", api.GetAuthzRole)
	app.Post("/api/authz/roles", api.CreateAuthzRole)
	app.Put("/api/authz/roles/:id", api.UpdateAuthzRole)
	app.Delete("/api/authz/roles/:id", api.DeleteAuthzRole)
	app.Get("/api/authz/policies", api.ListAuthzPolicies)
	app.Get("/api/authz/policies/:id", api.GetAuthzPolicy)
	app.Post("/api/authz/policies", api.CreateAuthzPolicy)
	app.Put("/api/authz/policies/:id", api.UpdateAuthzPolicy)
	app.Delete("/api/authz/policies/:id", api.DeleteAuthzPolicy)
	app.Get("/api/authz/acls", api.ListAuthzACLs)
	app.Post("/api/authz/acls", api.GrantAuthzACL)
	app.Delete("/api/authz/acls/:id", api.RevokeAuthzACL)
	app.Get("/api/authz/memberships/:subject", api.ListAuthzMemberships)
	app.Post("/api/authz/memberships", api.AssignAuthzMembership)
	app.Delete("/api/authz/memberships/:subject/:role", api.RevokeAuthzMembership)
	app.Post("/api/authz/explain", api.ExplainAuthz)
}

func (api *ConfigAPI) guard(c fiber.Ctx, op ConfigAPIOperation) error {
	if match := string(c.Request().Header.Peek("If-Match")); match != "" {
		c.Locals("tcpguard.config.if_match", match)
	} else if match := string(c.Request().Header.Peek("X-Config-If-Match")); match != "" {
		c.Locals("tcpguard.config.if_match", match)
	} else if match := string(c.Request().URI().QueryArgs().Peek("version")); match != "" {
		c.Locals("tcpguard.config.if_match", match)
	}
	c.Set("X-Config-Version", strconv.Itoa(api.currentVersion()))
	if api.unsafePublicAccess {
		return nil
	}
	if api.authzEngine != nil {
		allowed, decision, err := api.authorizeWithAuthz(c, op)
		if decision != nil {
			c.Locals("tcpguard.config.authz_decision", ConfigAPIAuthzDecision{
				Allowed:   decision.Allowed,
				Reason:    decision.Reason,
				MatchedBy: decision.MatchedBy,
				Trace:     decision.Trace,
			})
		}
		if err != nil {
			api.audit(c, op, "denied", map[string]any{"reason": err.Error()})
			return fiber.NewError(500, "config api authorization failed")
		}
		if !allowed {
			details := map[string]any{"reason": "authz denied"}
			if decision != nil {
				details["authz_reason"] = decision.Reason
				details["authz_matched_by"] = decision.MatchedBy
			}
			api.audit(c, op, "denied", details)
			return fiber.NewError(403, "config api authorization denied")
		}
		return nil
	}
	if api.authorizer != nil && api.authorizer(c, op) {
		return nil
	}
	api.audit(c, op, "denied", map[string]any{"reason": "unauthorized"})
	return fiber.NewError(403, "config api authorization required")
}

func (api *ConfigAPI) authorizeWithAuthz(c fiber.Ctx, op ConfigAPIOperation) (bool, *authz.Decision, error) {
	resolver := api.authzResolver
	if resolver == nil {
		resolver = DefaultConfigAPIAuthzResolver
	}
	subject, resource, env := resolver(c, op)
	if subject == nil || resource == nil || env == nil {
		return false, &authz.Decision{Allowed: false, Reason: "missing authz inputs"}, nil
	}
	decision, err := api.authzEngine.Authorize(context.Background(), subject, configAction(op.Action), resource, env)
	if err != nil {
		return false, decision, err
	}
	return decision != nil && decision.Allowed, decision, nil
}

func (api *ConfigAPI) checkVersion(c fiber.Ctx) bool {
	var match string
	if v := c.Locals("tcpguard.config.if_match"); v != nil {
		match, _ = v.(string)
	}
	return api.checkVersionValue(c, match)
}

func (api *ConfigAPI) checkVersionValue(c fiber.Ctx, match string) bool {
	if match == "" {
		return false
	}
	want, err := strconv.Atoi(match)
	if err != nil {
		_ = c.Status(400).JSON(fiber.Map{"error": "invalid If-Match config version"})
		return true
	}
	c.Locals("tcpguard.config.expected_version", want)
	current := api.currentVersion()
	if want != current {
		_ = c.Status(409).JSON(fiber.Map{
			"error":           "config version conflict",
			"current_version": current,
		})
		return true
	}
	return false
}

func (api *ConfigAPI) commitMutation(c fiber.Ctx, op ConfigAPIOperation) {
	expected := 0
	if v := c.Locals("tcpguard.config.expected_version"); v != nil {
		expected, _ = v.(int)
	}
	next := api.version + 1
	if versioned, ok := api.store.(VersionedConfigStore); ok {
		if version, err := versioned.CompareAndSwapConfigVersion(expected); err == nil && version > 0 {
			next = version
		}
	}
	api.version = next
	c.Set("X-Config-Version", strconv.Itoa(next))
	api.audit(c, op, "committed", map[string]any{"version": next})
}

func (api *ConfigAPI) currentVersion() int {
	if versioned, ok := api.store.(VersionedConfigStore); ok {
		if version, err := versioned.GetConfigVersion(); err == nil && version > 0 {
			api.version = version
		}
	}
	if api.version <= 0 {
		api.version = 1
	}
	return api.version
}

func (api *ConfigAPI) audit(c fiber.Ctx, op ConfigAPIOperation, decision string, details map[string]any) {
	if api.eventEmitter == nil {
		return
	}
	event := NewSecurityEvent("config_api_"+op.Action, "info")
	if op.Action == "delete" {
		event.Severity = "medium"
	}
	event.ClientIP = c.IP()
	event.UserID = c.Get("X-User-ID")
	event.Path = c.Path()
	event.Method = c.Method()
	event.Decision = decision
	event.RequestID = c.Get("X-Request-ID")
	event.TraceID = c.Get("X-Trace-ID")
	event.Details = map[string]any{
		"resource": op.Resource,
		"target":   op.Target,
	}
	if v := c.Locals("tcpguard.config.authz_decision"); v != nil {
		event.Details["authz"] = v
	}
	for k, v := range details {
		event.Details[k] = v
	}
	_ = api.eventEmitter.Emit(context.Background(), event)
}

func (api *ConfigAPI) validateCandidate(mutator func(*AnomalyConfig)) error {
	if api.validator == nil {
		return nil
	}
	cfg, err := api.store.LoadAll()
	if err != nil {
		return fmt.Errorf("load config for validation: %w", err)
	}
	if cfg == nil {
		cfg = &AnomalyConfig{}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("clone config for validation: %w", err)
	}
	var candidate AnomalyConfig
	if err := json.Unmarshal(data, &candidate); err != nil {
		return fmt.Errorf("clone config for validation: %w", err)
	}
	cfg = &candidate
	if cfg.AnomalyDetectionRules.Global.Rules == nil {
		cfg.AnomalyDetectionRules.Global.Rules = make(map[string]Rule)
	}
	if cfg.AnomalyDetectionRules.APIEndpoints == nil {
		cfg.AnomalyDetectionRules.APIEndpoints = make(map[string]EndpointRules)
	}
	mutator(cfg)
	return api.validator.Validate(cfg)
}

func (api *ConfigAPI) ListRules(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "rule", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	rules, err := api.store.ListRules()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(rules)})
	return c.JSON(rules)
}

func (api *ConfigAPI) GetRule(c fiber.Ctx) error {
	name := c.Params("name")
	op := ConfigAPIOperation{Resource: "rule", Action: "get", Target: name}
	if err := api.guard(c, op); err != nil {
		return err
	}
	rule, err := api.store.GetRule(name)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if rule == nil {
		return c.Status(404).JSON(fiber.Map{"error": "rule not found"})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(rule)
}

func (api *ConfigAPI) CreateRule(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "rule", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var rule Rule
	if err := c.Bind().Body(&rule); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = rule.Name
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		cfg.AnomalyDetectionRules.Global.Rules[rule.Name] = rule
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.CreateRule(&rule); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(201).JSON(rule)
}

func (api *ConfigAPI) UpdateRule(c fiber.Ctx) error {
	name := c.Params("name")
	op := ConfigAPIOperation{Resource: "rule", Action: "update", Target: name}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var rule Rule
	if err := c.Bind().Body(&rule); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	rule.Name = name
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		cfg.AnomalyDetectionRules.Global.Rules[name] = rule
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.UpdateRule(&rule); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.JSON(rule)
}

func (api *ConfigAPI) DeleteRule(c fiber.Ctx) error {
	name := c.Params("name")
	op := ConfigAPIOperation{Resource: "rule", Action: "delete", Target: name}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		delete(cfg.AnomalyDetectionRules.Global.Rules, name)
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.DeleteRule(name); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ListEndpoints(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "endpoint", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	endpoints, err := api.store.ListEndpoints()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(endpoints)})
	return c.JSON(endpoints)
}

func (api *ConfigAPI) GetEndpoint(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	op := ConfigAPIOperation{Resource: "endpoint", Action: "get", Target: endpoint}
	if err := api.guard(c, op); err != nil {
		return err
	}
	ep, err := api.store.GetEndpoint(endpoint)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if ep == nil {
		return c.Status(404).JSON(fiber.Map{"error": "endpoint not found"})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(ep)
}

func (api *ConfigAPI) CreateEndpoint(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "endpoint", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var endpoint EndpointRules
	if err := c.Bind().Body(&endpoint); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = endpoint.Endpoint
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		cfg.AnomalyDetectionRules.APIEndpoints[endpoint.Endpoint] = endpoint
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.CreateEndpoint(&endpoint); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(201).JSON(endpoint)
}

func (api *ConfigAPI) UpdateEndpoint(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	op := ConfigAPIOperation{Resource: "endpoint", Action: "update", Target: endpoint}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var ep EndpointRules
	if err := c.Bind().Body(&ep); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	ep.Endpoint = endpoint
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		cfg.AnomalyDetectionRules.APIEndpoints[endpoint] = ep
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.UpdateEndpoint(&ep); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.JSON(ep)
}

func (api *ConfigAPI) DeleteEndpoint(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	op := ConfigAPIOperation{Resource: "endpoint", Action: "delete", Target: endpoint}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		delete(cfg.AnomalyDetectionRules.APIEndpoints, endpoint)
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.DeleteEndpoint(endpoint); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) GetGlobalConfig(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "global", Action: "get"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	config, err := api.store.GetGlobalConfig()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(config)
}

func (api *ConfigAPI) UpdateGlobalConfig(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "global", Action: "update"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var config GlobalRules
	if err := c.Bind().Body(&config); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if err := api.validateCandidate(func(cfg *AnomalyConfig) {
		cfg.AnomalyDetectionRules.Global = config
	}); err != nil {
		api.audit(c, op, "rejected", map[string]any{"reason": err.Error()})
		return c.Status(400).JSON(fiber.Map{"error": "config validation failed", "details": err.Error()})
	}
	if err := api.store.UpdateGlobalConfig(&config); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.JSON(config)
}

func (api *ConfigAPI) ListUsers(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "user", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	users, err := api.store.ListUsers()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(users)})
	return c.JSON(users)
}

func (api *ConfigAPI) GetUser(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "user", Action: "get", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	user, err := api.store.GetUser(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if user == nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(user)
}

func (api *ConfigAPI) CreateUser(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "user", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var user User
	if err := c.Bind().Body(&user); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = user.ID
	if err := api.store.CreateUser(&user); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(201).JSON(user)
}

func (api *ConfigAPI) UpdateUser(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "user", Action: "update", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var user User
	if err := c.Bind().Body(&user); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	user.ID = id
	if err := api.store.UpdateUser(&user); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.JSON(user)
}

func (api *ConfigAPI) DeleteUser(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "user", Action: "delete", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	if err := api.store.DeleteUser(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ListGroups(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "group", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	groups, err := api.store.ListGroups()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(groups)})
	return c.JSON(groups)
}

func (api *ConfigAPI) GetGroup(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "group", Action: "get", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	group, err := api.store.GetGroup(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if group == nil {
		return c.Status(404).JSON(fiber.Map{"error": "group not found"})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(group)
}

func (api *ConfigAPI) CreateGroup(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "group", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var group Group
	if err := c.Bind().Body(&group); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = group.ID
	if err := api.store.CreateGroup(&group); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(201).JSON(group)
}

func (api *ConfigAPI) UpdateGroup(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "group", Action: "update", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	var group Group
	if err := c.Bind().Body(&group); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	group.ID = id
	if err := api.store.UpdateGroup(&group); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.JSON(group)
}

func (api *ConfigAPI) DeleteGroup(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "group", Action: "delete", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	if err := api.store.DeleteGroup(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) AddUserToGroup(c fiber.Ctx) error {
	userID := c.Params("userId")
	groupID := c.Params("groupId")
	op := ConfigAPIOperation{Resource: "user_group", Action: "create", Target: userID + ":" + groupID}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	if err := api.store.AddUserToGroup(userID, groupID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) RemoveUserFromGroup(c fiber.Ctx) error {
	userID := c.Params("userId")
	groupID := c.Params("groupId")
	op := ConfigAPIOperation{Resource: "user_group", Action: "delete", Target: userID + ":" + groupID}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if api.checkVersion(c) {
		return nil
	}
	if err := api.store.RemoveUserFromGroup(userID, groupID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.commitMutation(c, op)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) GetUserGroups(c fiber.Ctx) error {
	userID := c.Params("userId")
	op := ConfigAPIOperation{Resource: "user_group", Action: "list", Target: userID}
	if err := api.guard(c, op); err != nil {
		return err
	}
	groups, err := api.store.GetUserGroups(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(groups)})
	return c.JSON(groups)
}

func (api *ConfigAPI) GetGroupUsers(c fiber.Ctx) error {
	groupID := c.Params("groupId")
	op := ConfigAPIOperation{Resource: "group_user", Action: "list", Target: groupID}
	if err := api.guard(c, op); err != nil {
		return err
	}
	users, err := api.store.GetGroupUsers(groupID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(users)})
	return c.JSON(users)
}

func (api *ConfigAPI) ensureAuthzEngine(c fiber.Ctx) bool {
	if api.authzEngine == nil {
		_ = c.Status(404).JSON(fiber.Map{"error": "authz engine not configured"})
		return false
	}
	return true
}

func (api *ConfigAPI) authzTenant(c fiber.Ctx) string {
	tenant := c.Query("tenant")
	if tenant == "" {
		tenant = stringLocal(c, "tcpguard.tenant_id")
	}
	if tenant == "" {
		tenant = c.Get("X-Tenant-ID")
	}
	if tenant == "" {
		tenant = "default"
	}
	return tenant
}

func (api *ConfigAPI) ListAuthzRoles(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_role", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	roles, err := api.authzEngine.ListRoles(context.Background(), api.authzTenant(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(roles)})
	return c.JSON(roles)
}

func (api *ConfigAPI) GetAuthzRole(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_role", Action: "get", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	role, err := api.findAuthzRole(c, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if role == nil {
		return c.Status(404).JSON(fiber.Map{"error": "role not found"})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(role)
}

func (api *ConfigAPI) CreateAuthzRole(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_role", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var role authz.Role
	if err := c.Bind().Body(&role); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = role.ID
	if role.TenantID == "" {
		role.TenantID = api.authzTenant(c)
	}
	if err := api.authzEngine.CreateRole(context.Background(), &role); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(201).JSON(role)
}

func (api *ConfigAPI) UpdateAuthzRole(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_role", Action: "update", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var role authz.Role
	if err := c.Bind().Body(&role); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	role.ID = id
	if role.TenantID == "" {
		role.TenantID = api.authzTenant(c)
	}
	if err := api.authzEngine.UpdateRole(context.Background(), &role); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.JSON(role)
}

func (api *ConfigAPI) DeleteAuthzRole(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_role", Action: "delete", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	if err := api.authzEngine.DeleteRole(context.Background(), id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ListAuthzPolicies(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_policy", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	policies, err := api.authzEngine.ListPolicies(context.Background(), api.authzTenant(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(policies)})
	return c.JSON(policies)
}

func (api *ConfigAPI) GetAuthzPolicy(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_policy", Action: "get", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	policy, err := api.findAuthzPolicy(c, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if policy == nil {
		return c.Status(404).JSON(fiber.Map{"error": "policy not found"})
	}
	api.audit(c, op, "allowed", nil)
	return c.JSON(policy)
}

type authzPolicyPayload struct {
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant_id"`
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Priority  int      `json:"priority"`
	Enabled   *bool    `json:"enabled,omitempty"`
}

func (p authzPolicyPayload) toPolicy(defaultTenant string) *authz.Policy {
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	tenant := p.TenantID
	if tenant == "" {
		tenant = defaultTenant
	}
	actions := make([]authz.Action, 0, len(p.Actions))
	for _, action := range p.Actions {
		actions = append(actions, authz.Action(action))
	}
	effect := authz.EffectAllow
	if p.Effect == string(authz.EffectDeny) {
		effect = authz.EffectDeny
	}
	return &authz.Policy{
		ID:        p.ID,
		TenantID:  tenant,
		Effect:    effect,
		Actions:   actions,
		Resources: p.Resources,
		Condition: &authz.TrueExpr{},
		Priority:  p.Priority,
		Enabled:   enabled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (api *ConfigAPI) CreateAuthzPolicy(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_policy", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var payload authzPolicyPayload
	if err := c.Bind().Body(&payload); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	policy := payload.toPolicy(api.authzTenant(c))
	op.Target = policy.ID
	if err := api.authzEngine.CreatePolicy(context.Background(), policy); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(201).JSON(policy)
}

func (api *ConfigAPI) UpdateAuthzPolicy(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_policy", Action: "update", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var payload authzPolicyPayload
	if err := c.Bind().Body(&payload); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	payload.ID = id
	policy := payload.toPolicy(api.authzTenant(c))
	if err := api.authzEngine.UpdatePolicy(context.Background(), policy); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.JSON(policy)
}

func (api *ConfigAPI) DeleteAuthzPolicy(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_policy", Action: "delete", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	if err := api.authzEngine.DeletePolicy(context.Background(), id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ListAuthzACLs(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_acl", Action: "list"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	acls, err := api.authzEngine.ListACLs(context.Background(), api.authzTenant(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(acls)})
	return c.JSON(acls)
}

func (api *ConfigAPI) GrantAuthzACL(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_acl", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var acl authz.ACL
	if err := c.Bind().Body(&acl); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = acl.ID
	if acl.TenantID == "" {
		acl.TenantID = api.authzTenant(c)
	}
	if err := api.authzEngine.GrantACL(context.Background(), &acl); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(201).JSON(acl)
}

func (api *ConfigAPI) RevokeAuthzACL(c fiber.Ctx) error {
	id := c.Params("id")
	op := ConfigAPIOperation{Resource: "authz_acl", Action: "delete", Target: id}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	if err := api.authzEngine.RevokeACL(context.Background(), id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(204).Send(nil)
}

type authzMembershipPayload struct {
	SubjectID string `json:"subject_id"`
	RoleID    string `json:"role_id"`
}

func (api *ConfigAPI) ListAuthzMemberships(c fiber.Ctx) error {
	subject := c.Params("subject")
	op := ConfigAPIOperation{Resource: "authz_membership", Action: "list", Target: subject}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	roles, err := api.authzEngine.ListRolesForUser(context.Background(), subject)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"count": len(roles)})
	return c.JSON(fiber.Map{"subject_id": subject, "roles": roles})
}

func (api *ConfigAPI) AssignAuthzMembership(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_membership", Action: "create"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var payload authzMembershipPayload
	if err := c.Bind().Body(&payload); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	op.Target = payload.SubjectID + ":" + payload.RoleID
	if err := api.authzEngine.AssignRoleToUser(context.Background(), payload.SubjectID, payload.RoleID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) RevokeAuthzMembership(c fiber.Ctx) error {
	subject := c.Params("subject")
	role := c.Params("role")
	op := ConfigAPIOperation{Resource: "authz_membership", Action: "delete", Target: subject + ":" + role}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	if err := api.authzEngine.RevokeRoleFromUser(context.Background(), subject, role); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "committed", nil)
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ExplainAuthz(c fiber.Ctx) error {
	op := ConfigAPIOperation{Resource: "authz_explain", Action: "get"}
	if err := api.guard(c, op); err != nil {
		return err
	}
	if !api.ensureAuthzEngine(c) {
		return nil
	}
	var req authz.ExplainRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Tenant == "" {
		req.Tenant = api.authzTenant(c)
	}
	decision, err := api.authzEngine.ExplainRequest(context.Background(), &req)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	api.audit(c, op, "allowed", map[string]any{"authz_reason": decision.Reason, "authz_matched_by": decision.MatchedBy})
	return c.JSON(decision)
}

func (api *ConfigAPI) findAuthzRole(c fiber.Ctx, id string) (*authz.Role, error) {
	roles, err := api.authzEngine.ListRoles(context.Background(), api.authzTenant(c))
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		if role.ID == id {
			return role, nil
		}
	}
	return nil, nil
}

func (api *ConfigAPI) findAuthzPolicy(c fiber.Ctx, id string) (*authz.Policy, error) {
	policies, err := api.authzEngine.ListPolicies(context.Background(), api.authzTenant(c))
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if policy.ID == id {
			return policy, nil
		}
	}
	return nil, nil
}
