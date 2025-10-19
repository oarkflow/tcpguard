package tcpguard

import (
	"fmt"
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
		if endpointRule.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("endpoint %s has invalid rate limit: %d", endpoint, endpointRule.RateLimit.RequestsPerMinute)
		}
		for i, action := range endpointRule.Actions {
			if err := v.validateAction(fmt.Sprintf("endpoint %s action %d", endpoint, i), &action); err != nil {
				return err
			}
		}
	}
	
	return nil
}

func (v *DefaultConfigValidator) validateRule(name string, rule *Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule has empty name")
	}
	if rule.Type == "" {
		return fmt.Errorf("rule %s has empty type", name)
	}
	for i, action := range rule.Actions {
		if err := v.validateAction(fmt.Sprintf("rule %s action %d", name, i), &action); err != nil {
			return err
		}
	}
	return nil
}

func (v *DefaultConfigValidator) validateAction(context string, action *Action) error {
	if action.Type == "" {
		return fmt.Errorf("%s has empty type", context)
	}
	validTypes := []string{"rate_limit", "temporary_ban", "permanent_ban", "jitter_warning"}
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
	return nil
}
