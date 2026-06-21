package tcpguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/logger"
	authzstores "github.com/oarkflow/authz/stores"
)

type AuthzRequest struct {
	Policy    string
	RuleID    string
	Action    string
	Resource  string
	Subject   map[string]any
	Attrs     map[string]any
	Context   *Context
	EventType string
}

type AuthzEvidence struct {
	Provider  string         `json:"provider,omitempty"`
	Policy    string         `json:"policy,omitempty"`
	Allowed   bool           `json:"allowed"`
	Reason    string         `json:"reason,omitempty"`
	MatchedBy string         `json:"matched_by,omitempty"`
	Trace     []string       `json:"trace,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type AuthzDecision struct {
	Allowed  bool
	Evidence AuthzEvidence
}

type AuthzProvider interface {
	Authorize(context.Context, AuthzRequest) (AuthzDecision, error)
}

type AuthzErrorPolicy string

const (
	AuthzErrorDeny  AuthzErrorPolicy = "deny"
	AuthzErrorAllow AuthzErrorPolicy = "allow"
)

type AuthzConfig struct {
	File        string
	Strict      bool
	EnforceHTTP bool
	Timeout     time.Duration
	ErrorPolicy AuthzErrorPolicy
}

type OarkflowAuthzProvider struct {
	engine *authz.Engine
}

func NewOarkflowAuthzProviderFromFile(path string) (*OarkflowAuthzProvider, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("tcpguard: authz file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tcpguard: read authz config %q: %w", path, err)
	}
	loader := authz.NewConfigLoader()
	var cfg *authz.Config
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		cfg, err = loader.LoadJSON(data)
	} else {
		parser := authz.NewDSLParser()
		cfg, err = parser.Parse(data)
	}
	if err != nil {
		return nil, fmt.Errorf("tcpguard: parse authz config %q: %w", path, err)
	}
	if err := authz.ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("tcpguard: validate authz config %q: %w", path, err)
	}
	policyStore := authzstores.NewMemoryPolicyStore()
	roleStore := authzstores.NewMemoryRoleStore()
	aclStore := authzstores.NewMemoryACLStore()
	membershipStore := authzstores.NewMemoryRoleMembershipStore()
	tenantStore := authzstores.NewMemoryTenantStore()
	engine := authz.NewEngine(
		policyStore,
		roleStore,
		aclStore,
		authzstores.NewMemoryAuditStore(),
		authz.WithRoleMembershipStore(membershipStore),
		authz.WithTenantStore(tenantStore),
		authz.WithLogger(logger.NewNullLogger()),
	)
	ctx := context.Background()
	for _, tenant := range cfg.Tenants {
		if err := engine.CreateTenant(ctx, &authz.Tenant{ID: tenant.ID, Name: tenant.Name, ParentID: tenant.Parent, Attrs: tenant.Attrs}); err != nil {
			return nil, fmt.Errorf("tcpguard: apply authz tenant %q: %w", tenant.ID, err)
		}
	}
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		return nil, fmt.Errorf("tcpguard: apply authz config %q: %w", path, err)
	}
	// ApplyConfig reloads one tenant at a time, while PolicyIndex is global.
	// Rebuild once from every configured policy so multi-tenant files retain all
	// policy candidates.
	if err := engine.ReloadPolicies(ctx, ""); err != nil {
		return nil, fmt.Errorf("tcpguard: index authz policies %q: %w", path, err)
	}
	return &OarkflowAuthzProvider{engine: engine}, nil
}

// Engine returns the configured AuthZ engine. Applications that need runtime
// policy, role, ACL, tenant, or membership updates can use the regular AuthZ
// Engine API after loading the initial static DSL through TCPGuard.
func (p *OarkflowAuthzProvider) Engine() *authz.Engine {
	if p == nil {
		return nil
	}
	return p.engine
}

func (p *OarkflowAuthzProvider) Authorize(ctx context.Context, req AuthzRequest) (AuthzDecision, error) {
	if p == nil || p.engine == nil {
		return AuthzDecision{}, errors.New("authz provider is not initialized")
	}
	subjectID := strings.TrimSpace(asString(req.Subject["id"]))
	subjectAttrs := copyAnyMap(req.Attrs)
	if attrs, ok := req.Subject["attrs"].(map[string]any); ok {
		for key, value := range attrs {
			subjectAttrs[key] = value
		}
	}
	subject := &authz.Subject{
		ID:       subjectID,
		Type:     firstNonEmpty(asString(req.Subject["type"]), "user"),
		TenantID: asString(req.Subject["tenant_id"]),
		Roles:    asStringSlice(req.Subject["roles"]),
		Groups:   asStringSlice(req.Subject["groups"]),
		Attrs:    subjectAttrs,
	}
	resourceType, resourceID := splitAuthzResource(firstNonEmpty(req.Resource, "request"))
	resourceTenant := firstNonEmpty(asString(req.Attrs["resource.tenant_id"]), subject.TenantID)
	environmentTenant := firstNonEmpty(asString(req.Attrs["env.tenant_id"]), resourceTenant)
	resource := &authz.Resource{
		ID:       resourceID,
		Type:     resourceType,
		TenantID: resourceTenant,
		OwnerID:  asString(req.Attrs["resource.owner_id"]),
		Attrs: mergeAnyMaps(req.Attrs, map[string]any{
			"rule_id":    req.RuleID,
			"policy":     req.Policy,
			"event_type": req.EventType,
		}),
	}
	env := &authz.Environment{Time: time.Now().UTC(), TenantID: environmentTenant, Extra: req.Attrs}
	if rawIP := net.ParseIP(asString(req.Attrs["env.ip"])); rawIP != nil {
		env.IP = rawIP
	}
	env.Region = asString(req.Attrs["env.region"])
	decision, err := p.engine.Authorize(ctx, subject, authz.Action(firstNonEmpty(req.Action, "evaluate")), resource, env)
	if err != nil {
		return AuthzDecision{}, err
	}
	return AuthzDecision{
		Allowed: decision.Allowed,
		Evidence: AuthzEvidence{
			Provider:  "oarkflow/authz",
			Policy:    req.Policy,
			Allowed:   decision.Allowed,
			Reason:    decision.Reason,
			MatchedBy: decision.MatchedBy,
			Trace:     append([]string(nil), decision.Trace...),
		},
	}, nil
}

func authorizeHTTPContext(ctx context.Context, provider AuthzProvider, cfg AuthzConfig, sec *Context) (AuthzDecision, error) {
	if provider == nil || sec == nil {
		return AuthzDecision{Allowed: true}, nil
	}
	tenantID := firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant)
	subjectTenant := firstNonEmpty(sec.Identity.Tenant, tenantID)
	ownerID := ""
	if sec.Request.Params != nil {
		ownerID = firstNonEmpty(sec.Request.Params["owner_id"], sec.Request.Params["id"])
	}
	attrs := map[string]any{
		"resource.owner_id":  ownerID,
		"resource.tenant_id": tenantID,
		"env.tenant_id":      tenantID,
		"env.ip":             sec.Network.IP,
		"env.region":         sec.Network.Region,
		"request.path":       sec.Request.Path,
		"request.method":     sec.Request.Method,
	}
	for key, value := range sec.Extra {
		attrs[key] = value
	}
	req := AuthzRequest{
		Action:    strings.ToUpper(firstNonEmpty(sec.Request.Method, "GET")),
		Resource:  "route:" + strings.ToUpper(firstNonEmpty(sec.Request.Method, "GET")) + ":" + firstNonEmpty(sec.Request.Path, "/"),
		EventType: "request.received",
		Context:   sec,
		Subject: map[string]any{
			"id":        firstNonEmpty(sec.Identity.ID, "anonymous"),
			"type":      firstNonEmpty(sec.Identity.Type, "user"),
			"tenant_id": subjectTenant,
			"roles":     authzRoles(sec.Identity),
			"groups":    sec.Identity.Groups,
			"attrs":     sec.Identity.Attrs,
		},
		Attrs: attrs,
	}
	authzCtx := ctx
	cancel := func() {}
	if cfg.Timeout > 0 {
		authzCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
	}
	defer cancel()
	return provider.Authorize(authzCtx, req)
}

func splitAuthzResource(resource string) (string, string) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "resource", "request"
	}
	typ, id, ok := strings.Cut(resource, ":")
	if !ok || typ == "" || id == "" {
		return "resource", resource
	}
	return typ, id
}

func copyAnyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func mergeAnyMaps(values ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, value := range values {
		for key, item := range value {
			out[key] = item
		}
	}
	return out
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		if value == nil {
			return ""
		}
		data, _ := json.Marshal(value)
		return strings.Trim(string(data), "\"")
	}
}

func asStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := asString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
