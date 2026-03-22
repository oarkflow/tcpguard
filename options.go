package tcpguard

// RuleEngineOption configures optional components of the RuleEngine.
type RuleEngineOption func(*RuleEngine)

// WithStateStore sets a StateStore (superset of CounterStore) for advanced state management.
func WithStateStore(s StateStore) RuleEngineOption {
	return func(re *RuleEngine) {
		re.stateStore = s
	}
}

// WithEventEmitter sets an EventEmitter for publishing security events.
func WithEventEmitter(e EventEmitter) RuleEngineOption {
	return func(re *RuleEngine) { re.eventEmitter = e }
}

// WithRiskScorer sets a RiskScorer for adaptive risk evaluation.
func WithRiskScorer(r RiskScorer) RuleEngineOption {
	return func(re *RuleEngine) { re.riskScorer = r }
}

// WithPolicyEngine sets a PolicyEngine for declarative policy evaluation.
func WithPolicyEngine(p PolicyEngine) RuleEngineOption {
	return func(re *RuleEngine) { re.policyEngine = p }
}

// WithPlaybookRegistry sets a PlaybookRegistry for automated incident response.
func WithPlaybookRegistry(p PlaybookRegistry) RuleEngineOption {
	return func(re *RuleEngine) { re.playbookReg = p }
}

// WithCorrelationEngine sets a CorrelationEngine for cross-request event correlation.
func WithCorrelationEngine(c CorrelationEngine) RuleEngineOption {
	return func(re *RuleEngine) { re.correlationEngine = c }
}

// WithIdentityRiskAssessor sets an IdentityRiskAssessor for identity-based risk scoring.
func WithIdentityRiskAssessor(a IdentityRiskAssessor) RuleEngineOption {
	return func(re *RuleEngine) { re.identityRisk = a }
}

// ApplyOptions applies functional options to an existing RuleEngine.
func (re *RuleEngine) ApplyOptions(opts ...RuleEngineOption) {
	for _, opt := range opts {
		opt(re)
	}
}
