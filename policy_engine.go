package tcpguard

import (
	"context"
	"fmt"
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
	Version    int               `json:"version"`
	Layer      PolicyLayer       `json:"layer"`
	Priority   int               `json:"priority"`
	Conditions []PolicyCondition `json:"conditions"`
	Decision   Decision          `json:"decision"`
	Actions    []Action          `json:"actions"`
	Enabled    bool              `json:"enabled"`
	FailMode   string            `json:"failMode"`
}

// PolicyCondition defines a single condition within a policy.
type PolicyCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// PolicyVerdict is the result of policy evaluation.
type PolicyVerdict struct {
	Decision          Decision `json:"decision"`
	MatchedPolicyID   string   `json:"matched_policy_id"`
	MatchedPolicyName string   `json:"matched_policy_name"`
	Actions           []Action `json:"actions"`
	FailMode          string   `json:"fail_mode"`
	Version           int      `json:"version"`
}

// PolicyEngine evaluates requests against loaded policies.
type PolicyEngine interface {
	Evaluate(ctx context.Context, req *RiskRequest, signals []RiskSignal, riskScore float64) (*PolicyVerdict, error)
	LoadPolicies(policies []Policy) error
	GetPolicyVersion() int
}

// compiledCondition is a pre-compiled condition for efficient evaluation.
type compiledCondition struct {
	field    string
	operator string
	value    any
}

// evaluate checks whether the condition matches the given request context.
func (c *compiledCondition) evaluate(req *RiskRequest, signals []RiskSignal, riskScore float64) bool {
	var fieldVal any

	switch {
	case c.field == "risk_score":
		fieldVal = riskScore
	case c.field == "route_tier":
		fieldVal = float64(req.RouteTier)
	case c.field == "client_ip":
		fieldVal = req.IP
	case c.field == "method":
		fieldVal = req.Method
	case c.field == "path":
		fieldVal = req.Endpoint
	case c.field == "user_id":
		fieldVal = req.UserID
	case c.field == "device_id":
		fieldVal = req.DeviceFingerprint
	case c.field == "user_agent":
		fieldVal = req.UserAgent
	case strings.HasPrefix(c.field, "signal."):
		signalName := strings.TrimPrefix(c.field, "signal.")
		for _, s := range signals {
			if s.Name == signalName {
				fieldVal = s.Score
				break
			}
		}
		if fieldVal == nil {
			fieldVal = 0.0
		}
	default:
		return false
	}

	return compareValues(fieldVal, c.operator, c.value)
}

// compareValues performs the comparison between a field value and condition value.
func compareValues(fieldVal any, operator string, condVal any) bool {
	switch operator {
	case "eq":
		return fmt.Sprintf("%v", fieldVal) == fmt.Sprintf("%v", condVal)
	case "gt", "lt", "gte", "lte":
		fv := toFloat64(fieldVal)
		cv := toFloat64(condVal)
		switch operator {
		case "gt":
			return fv > cv
		case "lt":
			return fv < cv
		case "gte":
			return fv >= cv
		case "lte":
			return fv <= cv
		}
	case "in":
		sv := fmt.Sprintf("%v", fieldVal)
		if list, ok := condVal.([]any); ok {
			for _, item := range list {
				if fmt.Sprintf("%v", item) == sv {
					return true
				}
			}
		}
		return false
	case "contains":
		sv := fmt.Sprintf("%v", fieldVal)
		cv := fmt.Sprintf("%v", condVal)
		return strings.Contains(sv, cv)
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

// DefaultPolicyEngine implements PolicyEngine.
type DefaultPolicyEngine struct {
	mu                 sync.RWMutex
	policies           []Policy
	version            int
	compiledConditions map[string][]compiledCondition // policyID -> compiled conditions
}

// NewDefaultPolicyEngine creates a new DefaultPolicyEngine.
func NewDefaultPolicyEngine() *DefaultPolicyEngine {
	return &DefaultPolicyEngine{
		compiledConditions: make(map[string][]compiledCondition),
	}
}

// LoadPolicies stores, sorts, and compiles the given policies.
func (e *DefaultPolicyEngine) LoadPolicies(policies []Policy) error {
	sorted := make([]Policy, len(policies))
	copy(sorted, policies)

	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Layer != sorted[j].Layer {
			return sorted[i].Layer < sorted[j].Layer // Emergency (0) first
		}
		return sorted[i].Priority > sorted[j].Priority // Higher priority first within layer
	})

	compiled := make(map[string][]compiledCondition, len(sorted))
	for _, p := range sorted {
		conds := make([]compiledCondition, len(p.Conditions))
		for i, c := range p.Conditions {
			conds[i] = compiledCondition{
				field:    c.Field,
				operator: c.Operator,
				value:    c.Value,
			}
		}
		compiled[p.ID] = conds
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

		conds, ok := compiled[p.ID]
		if !ok {
			continue
		}

		// All conditions must match (AND logic)
		allMatch := true
		for _, c := range conds {
			if !c.evaluate(req, signals, riskScore) {
				allMatch = false
				break
			}
		}

		if allMatch {
			return &PolicyVerdict{
				Decision:          p.Decision,
				MatchedPolicyID:   p.ID,
				MatchedPolicyName: p.Name,
				Actions:           p.Actions,
				FailMode:          p.FailMode,
				Version:           version,
			}, nil
		}
	}

	// No policy matched: fail closed for sensitive routes, allow for others
	if req.RouteTier >= 2 {
		return &PolicyVerdict{
			Decision: Deny,
			FailMode: "closed",
			Version:  version,
		}, nil
	}

	return &PolicyVerdict{
		Decision: Allow,
		FailMode: "open",
		Version:  version,
	}, nil
}

// Ensure DefaultPolicyEngine implements PolicyEngine.
var _ PolicyEngine = (*DefaultPolicyEngine)(nil)
