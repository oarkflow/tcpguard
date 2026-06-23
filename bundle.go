package tcpguard

import (
	"context"
	"time"

	"github.com/oarkflow/condition"
)

type Bundle struct {
	Name          string
	Version       string
	BaseDir       string
	Mode          Mode
	Timezone      string
	DefaultEffect DecisionEffect
	DataSources   []DataSourceDefinition
	Lookups       []LookupDefinition
	Rules         []Rule
	Actions       []ActionDefinition
	Safety        PolicySafety
	DerivedEvents []DerivedTrigger
	Detectors     []DetectorDefinition
	Enrichers     []EnricherDefinition
	IntelFeeds    []IntelDefinition
	Baselines     []BaselineDefinition
	ThreatModels  []ThreatModelDefinition
	Authz         AuthzConfig
	Response      ResponseMessagePolicy
}

type PolicySafety struct {
	MaxRuleEvalTime    time.Duration
	MaxDetectorTimeout time.Duration
	MaxLookupTimeout   time.Duration
	MaxActionTimeout   time.Duration
	MaxActionsPerRule  int
	MaxLookupsPerEval  int
	MaxRetryCount      int
	MaxWebhookTimeout  time.Duration
	RequireSignature   bool
	RequireApprovalFor []string
	ActionAllowlist    []string
	CommandEnabled     bool
	AllowedDataSources []string
	ApprovalDataSource []string
}

type DataSourceDefinition struct {
	ID              string
	Type            string
	Prefix          string
	Path            string
	Key             string
	URL             string
	Method          string
	Driver          string
	DSN             string
	Timeout         time.Duration
	Headers         map[string]string
	CacheTTL        time.Duration
	CacheRefresh    time.Duration
	Watch           bool
	AllowPrivateURL bool
}

type LookupFallbackPolicy string

const (
	LookupFallbackAllow     LookupFallbackPolicy = "allow"
	LookupFallbackChallenge LookupFallbackPolicy = "challenge"
	LookupFallbackBlock     LookupFallbackPolicy = "block"
	LookupFallbackDefault   LookupFallbackPolicy = "default"
	LookupFallbackErrorFact LookupFallbackPolicy = "error_fact"
)

type LookupFallback struct {
	Policy LookupFallbackPolicy
	Reason string
	Value  map[string]any
}

type LookupDefinition struct {
	ID       string
	Source   string
	Mode     string
	Key      string
	Query    string
	Params   map[string]string
	Outputs  map[string]string
	Fallback LookupFallback
	Timeout  time.Duration
}

type DerivedTrigger struct {
	ID        string
	Source    string
	Condition string
	Emit      string
	compiled  *condition.Expression
}

type DetectorDefinition struct {
	ID       string
	Type     string
	Input    string
	Endpoint string
	Method   string
	Timeout  time.Duration
	Fallback string
	Fields   map[string]any
	Findings []DetectorFindingDefinition
	Outputs  map[string]any
}

type DetectorFindingDefinition struct {
	ID        string
	Condition string
	Risk      float64
	Message   string
	Fields    map[string]any
}

type EnricherDefinition struct {
	ID     string
	Type   string
	Source string
	Key    string
	Fields map[string]string
}

type IntelDefinition struct {
	ID      string
	Type    string
	Path    string
	URL     string
	Refresh time.Duration
	Match   string
	Fields  map[string]any
}

type BaselineDefinition struct {
	ID         string
	Entity     string
	Observe    string
	Window     time.Duration
	MinSamples int
	Fields     map[string]string
}

type BaselineValue struct {
	Count int64   `json:"count"`
	Mean  float64 `json:"mean"`
	M2    float64 `json:"m2"`
}

type BaselineSnapshot struct {
	Values map[string]BaselineValue `json:"values"`
}

type ThreatModelDefinition struct {
	ID         string
	Categories map[string][]string
}

func WithBundle(bundle Bundle) Option {
	return func(c *config) {
		if bundle.Mode != "" {
			c.mode = bundle.Mode
		}
		if bundle.Version != "" {
			c.policyVersion = bundle.Version
		}
		if bundle.DefaultEffect != "" {
			c.defaultEffect = bundle.DefaultEffect
		}
		if bundle.Authz.File != "" {
			c.authzConfig = bundle.Authz
		}
		if bundle.Authz.Strict {
			c.authzStrict = true
		}
		if bundle.Response.Environment != "" || bundle.Response.DetailLevel != "" {
			c.responsePolicy = bundle.Response
		}
		c.datasourceDefs = append(c.datasourceDefs, bundle.DataSources...)
		c.lookups = append(c.lookups, bundle.Lookups...)
		c.rules = append(c.rules, bundle.Rules...)
		c.safety = mergePolicySafety(c.safety, bundle.Safety)
		if c.actions == nil {
			c.actions = map[string]ActionDefinition{}
		}
		for _, action := range bundle.Actions {
			c.actions[action.ID] = action
		}
		c.derived = append(c.derived, bundle.DerivedEvents...)
		for _, intel := range bundle.IntelFeeds {
			if intel.Type == "file" && intel.Path != "" {
				c.intel = append(c.intel, &IndexedFileIntelFeed{Definition: intel, BaseDir: bundle.BaseDir})
			}
		}
		deps := DetectorDeps{
			Store:          c.store,
			IncidentStore:  c.incidentStore,
			ApprovalStore:  c.approvalStore,
			AuditStore:     c.auditStore,
			DataSources:    c.datasources,
			Lookups:        c.lookups,
			SecretProvider: c.secretProvider,
			Metrics:        c.metrics,
			Safety:         c.safety,
		}
		for _, detector := range bundle.Detectors {
			created, handled, err := newDetectorFromDefinition(detector, deps)
			if err != nil {
				localErr := err
				c.detectors = append(c.detectors, DetectorFunc{Name: "detector_config_error_" + detector.ID, Fn: func(context.Context, *Context, Event) ([]Finding, error) { return nil, localErr }})
				continue
			}
			if handled && created != nil {
				c.detectors = append(c.detectors, created)
			}
		}
		for _, enricher := range bundle.Enrichers {
			if enricher.Type == "lookup" {
				c.enrichers = append(c.enrichers, FileLookupEnricher{Definition: enricher})
			}
		}
		c.baselines = append(c.baselines, bundle.Baselines...)
		if len(bundle.ThreatModels) > 0 {
			c.threatModels = append(c.threatModels, bundle.ThreatModels...)
		}
	}
}

func abuseDetectorFromDefinition(def DetectorDefinition, store SecurityStore) AbuseDetector {
	detector := NewAbuseDetector(store)
	if def.Timeout > 0 {
		detector.Window = def.Timeout
	}
	if v, ok := durationField(def.Fields, "window"); ok {
		detector.Window = v
	}
	if v, ok := intField(def.Fields, "auth_ip_failure_threshold"); ok {
		detector.AuthIPFailureThreshold = v
	}
	if v, ok := intField(def.Fields, "auth_user_failure_threshold"); ok {
		detector.AuthUserFailureThreshold = v
	}
	if v, ok := intField(def.Fields, "password_spray_user_threshold"); ok {
		detector.PasswordSprayUserThreshold = v
	}
	if v, ok := intField(def.Fields, "api_key_ip_threshold"); ok {
		detector.APIKeyIPThreshold = v
	}
	if v, ok := intField(def.Fields, "api_key_user_threshold"); ok {
		detector.APIKeyUserThreshold = v
	}
	if v, ok := intField(def.Fields, "scan_path_threshold"); ok {
		detector.ScanPathThreshold = v
	}
	if v, ok := intField(def.Fields, "export_threshold"); ok {
		detector.ExportThreshold = v
	}
	if v, ok := intField(def.Fields, "function_invoke_threshold"); ok {
		detector.FunctionInvokeThreshold = v
	}
	if v, ok := intField(def.Fields, "user_agent_rotation_threshold"); ok {
		detector.UserAgentRotationThreshold = v
	}
	if v, ok := intField(def.Fields, "tenant_user_threshold"); ok {
		detector.TenantUserThreshold = v
	}
	if v, ok := intField(def.Fields, "account_enumeration_threshold"); ok {
		detector.AccountEnumerationThreshold = v
	}
	if v, ok := intField(def.Fields, "large_body_threshold"); ok {
		detector.LargeBodyThreshold = v
	}
	if v, ok := floatField(def.Fields, "payment_user_amount_threshold"); ok {
		detector.PaymentUserAmountThreshold = v
	}
	if v, ok := floatField(def.Fields, "payment_tenant_amount_threshold"); ok {
		detector.PaymentTenantAmountThreshold = v
	}
	if v, ok := floatField(def.Fields, "profile_risk_threshold"); ok {
		detector.ProfileRiskThreshold = v
	}
	return detector
}

func intField(fields map[string]any, key string) (int64, bool) {
	v, ok := floatField(fields, key)
	return int64(v), ok
}

func floatField(fields map[string]any, key string) (float64, bool) {
	if fields == nil {
		return 0, false
	}
	return number(fields[key])
}

func durationField(fields map[string]any, key string) (time.Duration, bool) {
	if fields == nil {
		return 0, false
	}
	switch v := fields[key].(type) {
	case time.Duration:
		return v, true
	case string:
		d, err := time.ParseDuration(v)
		return d, err == nil
	default:
		return 0, false
	}
}

func mergePolicySafety(base, override PolicySafety) PolicySafety {
	if override.MaxRuleEvalTime > 0 {
		base.MaxRuleEvalTime = override.MaxRuleEvalTime
	}
	if override.MaxDetectorTimeout > 0 {
		base.MaxDetectorTimeout = override.MaxDetectorTimeout
	}
	if override.MaxLookupTimeout > 0 {
		base.MaxLookupTimeout = override.MaxLookupTimeout
	}
	if override.MaxActionTimeout > 0 {
		base.MaxActionTimeout = override.MaxActionTimeout
	}
	if override.MaxActionsPerRule > 0 {
		base.MaxActionsPerRule = override.MaxActionsPerRule
	}
	if override.MaxLookupsPerEval > 0 {
		base.MaxLookupsPerEval = override.MaxLookupsPerEval
	}
	if override.MaxRetryCount > 0 {
		base.MaxRetryCount = override.MaxRetryCount
	}
	if override.MaxWebhookTimeout > 0 {
		base.MaxWebhookTimeout = override.MaxWebhookTimeout
	}
	if override.RequireSignature {
		base.RequireSignature = true
	}
	if len(override.RequireApprovalFor) > 0 {
		base.RequireApprovalFor = append([]string(nil), override.RequireApprovalFor...)
	}
	if len(override.ActionAllowlist) > 0 {
		base.ActionAllowlist = append([]string(nil), override.ActionAllowlist...)
	}
	if override.CommandEnabled {
		base.CommandEnabled = true
	}
	if len(override.AllowedDataSources) > 0 {
		base.AllowedDataSources = append([]string(nil), override.AllowedDataSources...)
	}
	if len(override.ApprovalDataSource) > 0 {
		base.ApprovalDataSource = append([]string(nil), override.ApprovalDataSource...)
	}
	return base
}
