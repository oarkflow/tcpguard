package tcpguard

import (
	"context"
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// PolicyLayer represents the priority layer of a policy.
type PolicyLayer int

const (
	PolicyEmergency    PolicyLayer = 0
	PolicyBehavioral   PolicyLayer = 1
	PolicyContextAware PolicyLayer = 2
	PolicyStatic       PolicyLayer = 3
)

// Policy defines a security policy with conditions and actions.
type Policy struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Schema     string            `json:"schema,omitempty"`
	Version    int               `json:"version"`
	Layer      PolicyLayer       `json:"layer"`
	Priority   int               `json:"priority"`
	Condition  *PolicyCondition  `json:"condition,omitempty"`
	Conditions []PolicyCondition `json:"conditions"`
	Decision   Decision          `json:"decision"`
	Actions    []Action          `json:"actions"`
	Enabled    bool              `json:"enabled"`
	FailMode   string            `json:"failMode"`
	Mode       string            `json:"mode,omitempty"` // enforce (default), dry_run, shadow
}

// PolicyCondition defines a schema-versioned DSL condition. A condition may be
// a leaf comparison or a nested boolean node using All, Any, and Not.
type PolicyCondition struct {
	All      []PolicyCondition `json:"all,omitempty"`
	Any      []PolicyCondition `json:"any,omitempty"`
	Not      *PolicyCondition  `json:"not,omitempty"`
	Field    string            `json:"field,omitempty"`
	Operator string            `json:"operator,omitempty"`
	Value    any               `json:"value,omitempty"`
}

// PolicyVerdict is the result of policy evaluation.
type PolicyVerdict struct {
	Decision          Decision `json:"decision"`
	MatchedPolicyID   string   `json:"matched_policy_id"`
	MatchedPolicyName string   `json:"matched_policy_name"`
	Actions           []Action `json:"actions"`
	FailMode          string   `json:"fail_mode"`
	Version           int      `json:"version"`
	Reason            string   `json:"reason,omitempty"`
	Explanation       []string `json:"explanation,omitempty"`
	Mode              string   `json:"mode,omitempty"`
	Enforced          bool     `json:"enforced"`
}

// PolicyEngine evaluates requests against loaded policies.
type PolicyEngine interface {
	Evaluate(ctx context.Context, req *RiskRequest, signals []RiskSignal, riskScore float64) (*PolicyVerdict, error)
	LoadPolicies(policies []Policy) error
	GetPolicyVersion() int
}

// compiledPolicy stores the normalized condition tree for a policy.
type compiledPolicy struct {
	condition *PolicyCondition
}

func normalizePolicyCondition(p Policy) *PolicyCondition {
	if p.Condition != nil {
		return p.Condition
	}
	if len(p.Conditions) == 0 {
		return &PolicyCondition{All: []PolicyCondition{}}
	}
	return &PolicyCondition{All: p.Conditions}
}

// compareValues performs the comparison between a field value and condition value.
func compareValues(fieldVal any, operator string, condVal any) bool {
	operator = strings.ToLower(strings.TrimSpace(operator))
	switch operator {
	case "eq", "equals":
		return fmt.Sprintf("%v", fieldVal) == fmt.Sprintf("%v", condVal)
	case "neq", "not_eq", "not_equals":
		return fmt.Sprintf("%v", fieldVal) != fmt.Sprintf("%v", condVal)
	case "gt", "lt", "gte", "lte", "between":
		fv := toFloat64(fieldVal)
		switch operator {
		case "gt":
			return fv > toFloat64(condVal)
		case "lt":
			return fv < toFloat64(condVal)
		case "gte":
			return fv >= toFloat64(condVal)
		case "lte":
			return fv <= toFloat64(condVal)
		case "between":
			bounds, ok := toAnySlice(condVal)
			if !ok || len(bounds) != 2 {
				return false
			}
			return fv >= toFloat64(bounds[0]) && fv <= toFloat64(bounds[1])
		}
	case "in":
		sv := fmt.Sprintf("%v", fieldVal)
		list, ok := toAnySlice(condVal)
		if !ok {
			return false
		}
		for _, item := range list {
			if fmt.Sprintf("%v", item) == sv {
				return true
			}
		}
	case "contains":
		sv := fmt.Sprintf("%v", fieldVal)
		cv := fmt.Sprintf("%v", condVal)
		return strings.Contains(sv, cv)
	case "starts_with", "prefix":
		return strings.HasPrefix(fmt.Sprintf("%v", fieldVal), fmt.Sprintf("%v", condVal))
	case "ends_with", "suffix":
		return strings.HasSuffix(fmt.Sprintf("%v", fieldVal), fmt.Sprintf("%v", condVal))
	case "glob", "matches_glob":
		ok, err := path.Match(fmt.Sprintf("%v", condVal), fmt.Sprintf("%v", fieldVal))
		return err == nil && ok
	case "regex", "matches_regex":
		re, err := regexp.Compile(fmt.Sprintf("%v", condVal))
		return err == nil && re.MatchString(fmt.Sprintf("%v", fieldVal))
	case "cidr", "in_cidr":
		ip := net.ParseIP(fmt.Sprintf("%v", fieldVal))
		if ip == nil {
			return false
		}
		for _, raw := range toStringList(condVal) {
			_, network, err := net.ParseCIDR(raw)
			if err == nil && network.Contains(ip) {
				return true
			}
		}
	case "exists":
		want := true
		if condVal != nil {
			want = toBool(condVal)
		}
		exists := fieldVal != nil && fmt.Sprintf("%v", fieldVal) != ""
		return exists == want
	}
	return false
}

// toFloat64 converts various types to float64 for numeric comparison.
func toFloat64(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case int32:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	default:
		return 0
	}
}

func toBool(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true") || val == "1" || strings.EqualFold(val, "yes")
	case int:
		return val != 0
	case float64:
		return val != 0
	default:
		return false
	}
}

func toAnySlice(v any) ([]any, bool) {
	switch val := v.(type) {
	case []any:
		return val, true
	case []string:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = item
		}
		return out, true
	case []int:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = item
		}
		return out, true
	case []float64:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = item
		}
		return out, true
	default:
		return nil, false
	}
}

func toStringList(v any) []string {
	if list, ok := toAnySlice(v); ok {
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	}
	return []string{fmt.Sprintf("%v", v)}
}

func resolvePolicyField(field string, req *RiskRequest, signals []RiskSignal, riskScore float64) (any, bool) {
	if req == nil {
		return nil, false
	}
	switch {
	case field == "risk_score":
		return riskScore, true
	case field == "route_tier":
		return float64(req.RouteTier), true
	case field == "client_ip" || field == "ip":
		if req.IP != "" {
			return req.IP, true
		}
		return req.ClientIP, true
	case field == "method":
		return req.Method, true
	case field == "path" || field == "endpoint":
		return req.Endpoint, true
	case field == "user_id":
		return req.UserID, true
	case field == "device_id":
		if req.DeviceID != "" {
			return req.DeviceID, true
		}
		return req.DeviceFingerprint, true
	case field == "device_fingerprint":
		return req.DeviceFingerprint, true
	case field == "user_agent":
		return req.UserAgent, true
	case strings.HasPrefix(field, "header."):
		if req.Headers == nil {
			return nil, false
		}
		name := strings.TrimPrefix(field, "header.")
		for k, v := range req.Headers {
			if strings.EqualFold(k, name) {
				return v, true
			}
		}
		return nil, false
	case strings.HasPrefix(field, "request.header."):
		return resolvePolicyField("header."+strings.TrimPrefix(field, "request.header."), req, signals, riskScore)
	case strings.HasPrefix(field, "signal."):
		signalName := strings.TrimPrefix(field, "signal.")
		for _, s := range signals {
			if s.Name == signalName {
				return s.Score, true
			}
		}
		return 0.0, true
	default:
		return nil, false
	}
}

func evaluatePolicyCondition(condition *PolicyCondition, req *RiskRequest, signals []RiskSignal, riskScore float64, explain *[]string) bool {
	if condition == nil {
		return true
	}
	if len(condition.All) == 0 && len(condition.Any) == 0 && condition.Not == nil && condition.Field == "" && condition.Operator == "" {
		if explain != nil {
			*explain = append(*explain, "empty=true")
		}
		return true
	}
	if len(condition.All) > 0 {
		for i := range condition.All {
			if !evaluatePolicyCondition(&condition.All[i], req, signals, riskScore, explain) {
				if explain != nil {
					*explain = append(*explain, "all=false")
				}
				return false
			}
		}
		if explain != nil {
			*explain = append(*explain, "all=true")
		}
		return true
	}
	if len(condition.Any) > 0 {
		for i := range condition.Any {
			if evaluatePolicyCondition(&condition.Any[i], req, signals, riskScore, explain) {
				if explain != nil {
					*explain = append(*explain, "any=true")
				}
				return true
			}
		}
		if explain != nil {
			*explain = append(*explain, "any=false")
		}
		return false
	}
	if condition.Not != nil {
		matched := !evaluatePolicyCondition(condition.Not, req, signals, riskScore, explain)
		if explain != nil {
			*explain = append(*explain, fmt.Sprintf("not=%v", matched))
		}
		return matched
	}

	fieldVal, exists := resolvePolicyField(condition.Field, req, signals, riskScore)
	if !exists && !strings.EqualFold(condition.Operator, "exists") {
		if explain != nil {
			*explain = append(*explain, fmt.Sprintf("%s unresolved", condition.Field))
		}
		return false
	}
	matched := compareValues(fieldVal, condition.Operator, condition.Value)
	if explain != nil {
		*explain = append(*explain, fmt.Sprintf("%s %s %v => %v", condition.Field, condition.Operator, condition.Value, matched))
	}
	return matched
}

func validatePolicyCondition(condition *PolicyCondition) error {
	if condition == nil {
		return nil
	}
	nested := 0
	if len(condition.All) > 0 {
		nested++
		for i := range condition.All {
			if err := validatePolicyCondition(&condition.All[i]); err != nil {
				return err
			}
		}
	}
	if len(condition.Any) > 0 {
		nested++
		for i := range condition.Any {
			if err := validatePolicyCondition(&condition.Any[i]); err != nil {
				return err
			}
		}
	}
	if condition.Not != nil {
		nested++
		if err := validatePolicyCondition(condition.Not); err != nil {
			return err
		}
	}
	isLeaf := condition.Field != "" || condition.Operator != ""
	if isLeaf {
		nested++
		if condition.Field == "" {
			return fmt.Errorf("condition field is required")
		}
		if condition.Operator == "" {
			return fmt.Errorf("condition operator is required for field %q", condition.Field)
		}
		switch strings.ToLower(condition.Operator) {
		case "regex", "matches_regex":
			if _, err := regexp.Compile(fmt.Sprintf("%v", condition.Value)); err != nil {
				return fmt.Errorf("invalid regex for field %q: %w", condition.Field, err)
			}
		case "glob", "matches_glob":
			if _, err := path.Match(fmt.Sprintf("%v", condition.Value), "probe"); err != nil {
				return fmt.Errorf("invalid glob for field %q: %w", condition.Field, err)
			}
		case "cidr", "in_cidr":
			for _, raw := range toStringList(condition.Value) {
				if _, _, err := net.ParseCIDR(raw); err != nil {
					return fmt.Errorf("invalid CIDR %q for field %q: %w", raw, condition.Field, err)
				}
			}
		case "between":
			bounds, ok := toAnySlice(condition.Value)
			if !ok || len(bounds) != 2 {
				return fmt.Errorf("between operator for field %q requires exactly two values", condition.Field)
			}
		}
	}
	if nested > 1 {
		return fmt.Errorf("condition must use exactly one of all, any, not, or leaf comparison")
	}
	return nil
}

// DefaultPolicyEngine implements PolicyEngine.
type DefaultPolicyEngine struct {
	mu                 sync.RWMutex
	policies           []Policy
	version            int
	compiledConditions map[string]compiledPolicy // policyID -> compiled condition tree
}

// NewDefaultPolicyEngine creates a new DefaultPolicyEngine.
func NewDefaultPolicyEngine() *DefaultPolicyEngine {
	return &DefaultPolicyEngine{
		compiledConditions: make(map[string]compiledPolicy),
	}
}

// LoadPolicies stores, sorts, and compiles the given policies.
func (e *DefaultPolicyEngine) LoadPolicies(policies []Policy) error {
	sorted := make([]Policy, len(policies))
	copy(sorted, policies)
	seen := make(map[string]struct{}, len(sorted))
	for _, p := range sorted {
		if p.ID == "" {
			return fmt.Errorf("policy id is required")
		}
		if _, exists := seen[p.ID]; exists {
			return fmt.Errorf("duplicate policy id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		if err := validatePolicyCondition(normalizePolicyCondition(p)); err != nil {
			return fmt.Errorf("invalid policy %q condition: %w", p.ID, err)
		}
		if p.Mode != "" && p.Mode != "enforce" && p.Mode != "dry_run" && p.Mode != "shadow" {
			return fmt.Errorf("invalid policy %q mode %q", p.ID, p.Mode)
		}
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Layer != sorted[j].Layer {
			return sorted[i].Layer < sorted[j].Layer // Emergency (0) first
		}
		return sorted[i].Priority > sorted[j].Priority // Higher priority first within layer
	})

	compiled := make(map[string]compiledPolicy, len(sorted))
	for _, p := range sorted {
		compiled[p.ID] = compiledPolicy{condition: normalizePolicyCondition(p)}
	}

	e.mu.Lock()
	e.policies = sorted
	e.compiledConditions = compiled
	e.version++
	e.mu.Unlock()

	return nil
}

// GetPolicyVersion returns the current policy version.
func (e *DefaultPolicyEngine) GetPolicyVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.version
}

// Evaluate iterates policies by layer order. First match wins.
func (e *DefaultPolicyEngine) Evaluate(ctx context.Context, req *RiskRequest, signals []RiskSignal, riskScore float64) (*PolicyVerdict, error) {
	e.mu.RLock()
	policies := e.policies
	compiled := e.compiledConditions
	version := e.version
	e.mu.RUnlock()

	for _, p := range policies {
		if !p.Enabled {
			continue
		}

		cp, ok := compiled[p.ID]
		if !ok {
			continue
		}

		explanation := []string{}
		if evaluatePolicyCondition(cp.condition, req, signals, riskScore, &explanation) {
			mode := p.Mode
			if mode == "" {
				mode = "enforce"
			}
			decision := p.Decision
			enforced := mode == "enforce"
			if !enforced {
				decision = Allow
			}
			return &PolicyVerdict{
				Decision:          decision,
				MatchedPolicyID:   p.ID,
				MatchedPolicyName: p.Name,
				Actions:           p.Actions,
				FailMode:          p.FailMode,
				Version:           version,
				Reason:            "matched policy",
				Explanation:       explanation,
				Mode:              mode,
				Enforced:          enforced,
			}, nil
		}
	}

	// No policy matched: fail closed for sensitive routes, allow for others
	if req.RouteTier >= 2 {
		return &PolicyVerdict{
			Decision: Deny,
			FailMode: "closed",
			Version:  version,
			Reason:   "no policy matched sensitive route",
			Enforced: true,
		}, nil
	}

	return &PolicyVerdict{
		Decision: Allow,
		FailMode: "open",
		Version:  version,
		Reason:   "no policy matched",
		Enforced: true,
	}, nil
}

// Ensure DefaultPolicyEngine implements PolicyEngine.
var _ PolicyEngine = (*DefaultPolicyEngine)(nil)
