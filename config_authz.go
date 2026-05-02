package tcpguard

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/authz"
	authzstores "github.com/oarkflow/authz/stores"
)

const (
	ConfigRoleViewer = "config_viewer"
	ConfigRoleEditor = "config_editor"
	ConfigRoleAdmin  = "config_admin"
)

// ConfigAPIAuthzResolver maps a Fiber request and config operation to authz inputs.
type ConfigAPIAuthzResolver func(c fiber.Ctx, op ConfigAPIOperation) (*authz.Subject, *authz.Resource, *authz.Environment)

// ConfigAPIAuthzDecision captures the latest authz decision for audit details.
type ConfigAPIAuthzDecision struct {
	Allowed   bool     `json:"allowed"`
	Reason    string   `json:"reason,omitempty"`
	MatchedBy string   `json:"matched_by,omitempty"`
	Trace     []string `json:"trace,omitempty"`
}

func configAction(action string) authz.Action {
	return authz.Action(action)
}

func configResourceType(resource string) string {
	switch resource {
	case "rule":
		return "config.rule"
	case "endpoint":
		return "config.endpoint"
	case "global":
		return "config.global"
	case "user":
		return "config.user"
	case "group":
		return "config.group"
	case "user_group", "group_user":
		return "config.user_group"
	case "authz_role":
		return "config.authz.role"
	case "authz_policy":
		return "config.authz.policy"
	case "authz_acl":
		return "config.authz.acl"
	case "authz_membership":
		return "config.authz.membership"
	case "authz_explain":
		return "config.authz.explain"
	default:
		return "config." + strings.ReplaceAll(resource, "_", ".")
	}
}

func configResourceID(op ConfigAPIOperation) string {
	target := op.Target
	if target == "" {
		target = "*"
	}
	return target
}

func configResourcePattern(resource string, target string) string {
	if target == "" {
		target = "*"
	}
	return configResourceType(resource) + ":" + target
}

// DefaultConfigAPIAuthzResolver trusts identity written by authentication middleware
// into Fiber locals. It does not trust identity headers.
func DefaultConfigAPIAuthzResolver(c fiber.Ctx, op ConfigAPIOperation) (*authz.Subject, *authz.Resource, *authz.Environment) {
	tenantID := stringLocal(c, "tcpguard.tenant_id")
	if tenantID == "" {
		tenantID = "default"
	}
	subject := &authz.Subject{
		ID:       stringLocal(c, "tcpguard.user_id"),
		Type:     "user",
		TenantID: tenantID,
		Roles:    stringSliceLocal(c, "tcpguard.user_roles"),
		Groups:   stringSliceLocal(c, "tcpguard.user_groups"),
		Attrs: map[string]any{
			"ip":          c.IP(),
			"method":      c.Method(),
			"path":        c.Path(),
			"request_id":  c.Get("X-Request-ID"),
			"config_op":   op.Action,
			"config_type": op.Resource,
			"config_id":   op.Target,
		},
	}
	if subject.ID == "" {
		subject.ID = "anonymous"
	}
	resource := &authz.Resource{
		ID:       configResourceID(op),
		Type:     configResourceType(op.Resource),
		TenantID: tenantID,
		Attrs: map[string]any{
			"operation": op.Action,
			"target":    op.Target,
		},
	}
	env := &authz.Environment{
		Time:     time.Now(),
		IP:       net.ParseIP(c.IP()),
		TenantID: tenantID,
		Extra: map[string]any{
			"path":       c.Path(),
			"method":     c.Method(),
			"request_id": c.Get("X-Request-ID"),
		},
	}
	return subject, resource, env
}

// HeaderConfigAPIAuthzResolver is intended only for demos/tests that do not have
// authentication middleware populating trusted locals.
func HeaderConfigAPIAuthzResolver(c fiber.Ctx, op ConfigAPIOperation) (*authz.Subject, *authz.Resource, *authz.Environment) {
	c.Locals("tcpguard.user_id", c.Get("X-User-ID"))
	c.Locals("tcpguard.user_roles", splitCSV(c.Get("X-User-Roles")))
	c.Locals("tcpguard.user_groups", splitCSV(c.Get("X-User-Groups")))
	if tenant := c.Get("X-Tenant-ID"); tenant != "" {
		c.Locals("tcpguard.tenant_id", tenant)
	}
	return DefaultConfigAPIAuthzResolver(c, op)
}

// NewDefaultConfigAPIAuthzEngine returns an authz engine with in-memory stores
// and TCPGuard's built-in config roles.
func NewDefaultConfigAPIAuthzEngine() *authz.Engine {
	policyStore := authzstores.NewMemoryPolicyStore()
	roleStore := authzstores.NewMemoryRoleStore()
	aclStore := authzstores.NewMemoryACLStore()
	auditStore := authzstores.NewMemoryAuditStore()
	memberships := authzstores.NewMemoryRoleMembershipStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore, authz.WithRoleMembershipStore(memberships))
	ctx := context.Background()
	_ = engine.CreateRole(ctx, &authz.Role{
		ID:       ConfigRoleViewer,
		TenantID: "default",
		Name:     ConfigRoleViewer,
		Permissions: []authz.Permission{
			{Action: "list", Resource: "config.*:*"},
			{Action: "get", Resource: "config.*:*"},
		},
	})
	_ = engine.CreateRole(ctx, &authz.Role{
		ID:       ConfigRoleEditor,
		TenantID: "default",
		Name:     ConfigRoleEditor,
		Inherits: []string{ConfigRoleViewer},
		Permissions: []authz.Permission{
			{Action: "create", Resource: "config.rule:*"},
			{Action: "update", Resource: "config.rule:*"},
			{Action: "delete", Resource: "config.rule:*"},
			{Action: "create", Resource: "config.endpoint:*"},
			{Action: "update", Resource: "config.endpoint:*"},
			{Action: "delete", Resource: "config.endpoint:*"},
			{Action: "update", Resource: "config.global:*"},
		},
	})
	_ = engine.CreateRole(ctx, &authz.Role{
		ID:       ConfigRoleAdmin,
		TenantID: "default",
		Name:     ConfigRoleAdmin,
		Inherits: []string{ConfigRoleEditor},
		Permissions: []authz.Permission{
			{Action: "*", Resource: "config.*:*"},
		},
	})
	return engine
}

func stringLocal(c fiber.Ctx, key string) string {
	if v := c.Locals(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func stringSliceLocal(c fiber.Ctx, key string) []string {
	if v := c.Locals(key); v != nil {
		switch items := v.(type) {
		case []string:
			return append([]string(nil), items...)
		case []any:
			out := make([]string, 0, len(items))
			for _, item := range items {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			return out
		case string:
			return splitCSV(items)
		}
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
