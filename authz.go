package tcpguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oarkflow/authz"
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
	if ext == ".yaml" || ext == ".yml" {
		cfg, err = loader.LoadYAML(data)
	} else if ext == ".json" {
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
	engine := authz.NewEngine(
		&authzPolicyStore{byID: indexPolicies(cfg.Policies)},
		&authzRoleStore{byID: indexRoles(cfg.Roles)},
		&authzACLStore{byID: indexACLs(cfg.ACLs)},
		authzNoopAuditStore{},
		authz.WithRoleMembershipStore(&authzRoleMembershipStore{subjectRoles: indexMemberships(cfg.Memberships)}),
	)
	return &OarkflowAuthzProvider{engine: engine}, nil
}

func (p *OarkflowAuthzProvider) Authorize(ctx context.Context, req AuthzRequest) (AuthzDecision, error) {
	if p == nil || p.engine == nil {
		return AuthzDecision{}, errors.New("authz provider is not initialized")
	}
	subject := &authz.Subject{
		ID:       normalizeAuthzSubjectID(asString(req.Subject["id"])),
		Type:     firstNonEmpty(asString(req.Subject["type"]), "user"),
		TenantID: asString(req.Subject["tenant_id"]),
		Roles:    asStringSlice(req.Subject["roles"]),
		Attrs:    req.Attrs,
	}
	resourceType, resourceID := splitAuthzResource(firstNonEmpty(req.Resource, "request"))
	resource := &authz.Resource{
		ID:       resourceID,
		Type:     resourceType,
		TenantID: asString(req.Subject["tenant_id"]),
		OwnerID:  asString(req.Attrs["resource.owner_id"]),
		Attrs: map[string]any{
			"rule_id":    req.RuleID,
			"policy":     req.Policy,
			"event_type": req.EventType,
		},
	}
	env := &authz.Environment{Time: time.Now().UTC(), TenantID: asString(req.Subject["tenant_id"]), Extra: req.Attrs}
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

func splitAuthzResource(resource string) (string, string) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "resource", "request"
	}
	typ, id, ok := strings.Cut(resource, ":")
	if !ok || typ == "" || id == "" {
		return "resource", resource
	}
	switch typ {
	case "route":
		return typ, id
	default:
		return "resource", resource
	}
}

func normalizeAuthzSubjectID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if strings.Contains(id, ":") {
		return id
	}
	return "user:" + id
}

func indexPolicies(values []*authz.Policy) map[string]*authz.Policy {
	out := make(map[string]*authz.Policy, len(values))
	for _, value := range values {
		if value != nil && value.ID != "" {
			out[value.ID] = value
		}
	}
	return out
}

func indexRoles(values []*authz.Role) map[string]*authz.Role {
	out := make(map[string]*authz.Role, len(values))
	for _, value := range values {
		if value != nil && value.ID != "" {
			out[value.ID] = value
		}
	}
	return out
}

func indexACLs(values []*authz.ACL) map[string]*authz.ACL {
	out := make(map[string]*authz.ACL, len(values))
	for _, value := range values {
		if value != nil && value.ID != "" {
			out[value.ID] = value
		}
	}
	return out
}

func indexMemberships(values []authz.RoleMembership) map[string][]string {
	out := map[string][]string{}
	for _, value := range values {
		value.SubjectID = strings.TrimSpace(value.SubjectID)
		value.RoleID = strings.TrimSpace(value.RoleID)
		if value.SubjectID == "" || value.RoleID == "" {
			continue
		}
		out[value.SubjectID] = append(out[value.SubjectID], value.RoleID)
	}
	return out
}

type authzPolicyStore struct{ byID map[string]*authz.Policy }

func (s *authzPolicyStore) CreatePolicy(context.Context, *authz.Policy) error {
	return errors.New("read-only")
}
func (s *authzPolicyStore) UpdatePolicy(context.Context, *authz.Policy) error {
	return errors.New("read-only")
}
func (s *authzPolicyStore) DeletePolicy(context.Context, string) error {
	return errors.New("read-only")
}
func (s *authzPolicyStore) GetPolicy(_ context.Context, id string) (*authz.Policy, error) {
	return s.byID[id], nil
}
func (s *authzPolicyStore) GetPolicyHistory(context.Context, string) ([]*authz.Policy, error) {
	return nil, nil
}
func (s *authzPolicyStore) ListPolicies(_ context.Context, tenantID string) ([]*authz.Policy, error) {
	var out []*authz.Policy
	for _, value := range s.byID {
		if tenantID == "" || value.TenantID == tenantID {
			out = append(out, value)
		}
	}
	return out, nil
}

type authzRoleStore struct{ byID map[string]*authz.Role }

func (s *authzRoleStore) CreateRole(context.Context, *authz.Role) error {
	return errors.New("read-only")
}
func (s *authzRoleStore) UpdateRole(context.Context, *authz.Role) error {
	return errors.New("read-only")
}
func (s *authzRoleStore) DeleteRole(context.Context, string) error { return errors.New("read-only") }
func (s *authzRoleStore) GetRole(_ context.Context, id string) (*authz.Role, error) {
	return s.byID[id], nil
}
func (s *authzRoleStore) ListRoles(_ context.Context, tenantID string) ([]*authz.Role, error) {
	var out []*authz.Role
	for _, value := range s.byID {
		if tenantID == "" || value.TenantID == tenantID {
			out = append(out, value)
		}
	}
	return out, nil
}

type authzACLStore struct{ byID map[string]*authz.ACL }

func (s *authzACLStore) GrantACL(context.Context, *authz.ACL) error  { return errors.New("read-only") }
func (s *authzACLStore) RevokeACL(context.Context, string) error     { return errors.New("read-only") }
func (s *authzACLStore) UpdateACL(context.Context, *authz.ACL) error { return errors.New("read-only") }
func (s *authzACLStore) GetACL(_ context.Context, id string) (*authz.ACL, error) {
	return s.byID[id], nil
}
func (s *authzACLStore) ListACLs(_ context.Context, tenantID string) ([]*authz.ACL, error) {
	var out []*authz.ACL
	for _, value := range s.byID {
		if tenantID == "" || value.TenantID == tenantID {
			out = append(out, value)
		}
	}
	return out, nil
}
func (s *authzACLStore) ListACLsByResource(_ context.Context, resourceID string) ([]*authz.ACL, error) {
	var out []*authz.ACL
	for _, value := range s.byID {
		if value.ResourceID == resourceID {
			out = append(out, value)
		}
	}
	return out, nil
}
func (s *authzACLStore) ListACLsBySubject(_ context.Context, subjectID string) ([]*authz.ACL, error) {
	var out []*authz.ACL
	for _, value := range s.byID {
		if value.SubjectID == subjectID {
			out = append(out, value)
		}
	}
	return out, nil
}

type authzNoopAuditStore struct{}

func (authzNoopAuditStore) LogDecision(context.Context, *authz.AuditEntry) error {
	return nil
}

func (authzNoopAuditStore) GetAccessLog(context.Context, authz.AuditFilter) ([]*authz.AuditEntry, error) {
	return nil, nil
}

type authzRoleMembershipStore struct{ subjectRoles map[string][]string }

func (s *authzRoleMembershipStore) AssignRole(context.Context, string, string) error {
	return errors.New("read-only")
}
func (s *authzRoleMembershipStore) RevokeRole(context.Context, string, string) error {
	return errors.New("read-only")
}
func (s *authzRoleMembershipStore) ListRoles(_ context.Context, subjectID string) ([]string, error) {
	return append([]string(nil), s.subjectRoles[subjectID]...), nil
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
