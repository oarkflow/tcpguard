package tcpguard

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

type DefaultConfigValidator struct{}

func NewDefaultConfigValidator() *DefaultConfigValidator {
	return &DefaultConfigValidator{}
}

func (v *DefaultConfigValidator) Validate(config *AnomalyConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	if config.AnomalyDetectionRules.Global.Rules == nil {
		config.AnomalyDetectionRules.Global.Rules = make(map[string]Rule)
	}
	if err := v.validateGlobalRules(&config.AnomalyDetectionRules.Global); err != nil {
		return err
	}

	// Validate global rules
	for name, rule := range config.AnomalyDetectionRules.Global.Rules {
		if err := v.validateRule(name, &rule); err != nil {
			return fmt.Errorf("invalid global rule %s: %v", name, err)
		}
	}

	// Validate endpoint rules
	for endpoint, endpointRule := range config.AnomalyDetectionRules.APIEndpoints {
		if endpoint == "" {
			return fmt.Errorf("endpoint rule has empty endpoint")
		}
		if endpointRule.Endpoint != "" && endpointRule.Endpoint != endpoint {
			return fmt.Errorf("endpoint key %s does not match endpoint value %s", endpoint, endpointRule.Endpoint)
		}
		if endpointRule.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("endpoint %s has invalid rate limit: %d", endpoint, endpointRule.RateLimit.RequestsPerMinute)
		}
		if endpointRule.RateLimit.Burst < 0 {
			return fmt.Errorf("endpoint %s has invalid burst: %d", endpoint, endpointRule.RateLimit.Burst)
		}
		for i, action := range endpointRule.Actions {
			if err := v.validateAction(fmt.Sprintf("endpoint %s action %d", endpoint, i), &action); err != nil {
				return err
			}
		}
	}

	return nil
}

func (v *DefaultConfigValidator) validateGlobalRules(global *GlobalRules) error {
	for _, cidr := range global.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid allowCIDR %q: %w", cidr, err)
		}
	}
	for _, cidr := range global.DenyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid denyCIDR %q: %w", cidr, err)
		}
	}
	for _, cidr := range global.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid trustedProxyCIDR %q: %w", cidr, err)
		}
	}
	if global.TrustProxy && len(global.TrustedProxyCIDRs) == 0 {
		return fmt.Errorf("trustProxy requires at least one trustedProxyCIDR")
	}
	if global.BanEscalationConfig != nil {
		if global.BanEscalationConfig.TempThreshold < 0 {
			return fmt.Errorf("banEscalation tempThreshold cannot be negative")
		}
		if global.BanEscalationConfig.Window != "" {
			if _, err := time.ParseDuration(global.BanEscalationConfig.Window); err != nil {
				return fmt.Errorf("invalid banEscalation window %q: %w", global.BanEscalationConfig.Window, err)
			}
		}
	}
	return nil
}

func (v *DefaultConfigValidator) validateRule(name string, rule *Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule has empty name")
	}
	if name != "" && name != rule.Name {
		return fmt.Errorf("rule key %s does not match rule name %s", name, rule.Name)
	}
	if rule.Type == "" {
		return fmt.Errorf("rule %s has empty type", name)
	}
	if rule.Priority < 0 {
		return fmt.Errorf("rule %s has negative priority: %d", name, rule.Priority)
	}
	for _, pattern := range append(rule.Endpoints, rule.ExcludePaths...) {
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("rule %s has empty endpoint pattern", name)
		}
	}
	for _, method := range append(rule.Methods, rule.ExcludeMethods...) {
		if method == "" {
			return fmt.Errorf("rule %s has empty method", name)
		}
	}
	if err := v.validateRuleParams(name, rule); err != nil {
		return err
	}
	for i, action := range rule.Actions {
		if err := v.validateAction(fmt.Sprintf("rule %s action %d", name, i), &action); err != nil {
			return err
		}
	}
	return nil
}

func (v *DefaultConfigValidator) validateRuleParams(name string, rule *Rule) error {
	for key, val := range rule.Params {
		if val == nil {
			return fmt.Errorf("rule %s param %s is null", name, key)
		}
		if strings.Contains(strings.ToLower(key), "window") || strings.Contains(strings.ToLower(key), "duration") {
			if s, ok := val.(string); ok && s != "" {
				if _, err := time.ParseDuration(s); err != nil {
					return fmt.Errorf("rule %s param %s has invalid duration %q: %w", name, key, s, err)
				}
			}
		}
		if strings.Contains(strings.ToLower(key), "threshold") || strings.Contains(strings.ToLower(key), "rate") || strings.Contains(strings.ToLower(key), "limit") {
			if f, ok := numericParam(val); ok && (math.IsNaN(f) || math.IsInf(f, 0) || f < 0) {
				return fmt.Errorf("rule %s param %s has invalid numeric value %v", name, key, val)
			}
		}
	}
	return nil
}

func (v *DefaultConfigValidator) validateAction(context string, action *Action) error {
	if action.Type == "" {
		return fmt.Errorf("%s has empty type", context)
	}
	validTypes := []string{"rate_limit", "temporary_ban", "permanent_ban", "jitter_warning", "restrict", "restrict_access"}
	valid := false
	for _, t := range validTypes {
		if action.Type == t {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("%s has invalid type: %s", context, action.Type)
	}
	if action.Response.Status < 100 || action.Response.Status > 599 {
		return fmt.Errorf("%s has invalid status code: %d", context, action.Response.Status)
	}
	if action.Priority < 0 {
		return fmt.Errorf("%s has negative priority: %d", context, action.Priority)
	}
	if action.Duration != "" {
		if _, err := time.ParseDuration(action.Duration); err != nil {
			return fmt.Errorf("%s has invalid duration %q: %w", context, action.Duration, err)
		}
	}
	if action.Limit != "" {
		if _, err := time.ParseDuration(action.Limit); err == nil {
			return fmt.Errorf("%s limit should be a rate/quantity, not a duration", context)
		}
	}
	if len(action.JitterRangeMs) > 0 {
		if len(action.JitterRangeMs) != 2 {
			return fmt.Errorf("%s jitterRangeMs requires exactly two values", context)
		}
		if action.JitterRangeMs[0] < 0 || action.JitterRangeMs[1] < action.JitterRangeMs[0] {
			return fmt.Errorf("%s has invalid jitterRangeMs", context)
		}
	}
	if action.Trigger != nil {
		if err := v.validateTrigger(context, action.Trigger); err != nil {
			return err
		}
	}
	return nil
}

func (v *DefaultConfigValidator) validateTrigger(context string, trigger *Trigger) error {
	for key, val := range *trigger {
		if val == nil {
			return fmt.Errorf("%s trigger %s is null", context, key)
		}
		switch key {
		case "within", "window":
			s, ok := val.(string)
			if !ok || s == "" {
				return fmt.Errorf("%s trigger %s must be a duration string", context, key)
			}
			if _, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("%s trigger %s has invalid duration %q: %w", context, key, s, err)
			}
		case "threshold":
			if f, ok := numericParam(val); !ok || f < 0 {
				return fmt.Errorf("%s trigger threshold must be a non-negative number", context)
			}
		}
	}
	return nil
}

func numericParam(v any) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	case float32:
		return float64(val), true
	default:
		return 0, false
	}
}
