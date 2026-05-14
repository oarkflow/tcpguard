package tcpguard

import (
	"time"

	"github.com/oarkflow/condition"
)

type Bundle struct {
	Name          string
	Version       string
	BaseDir       string
	Mode          Mode
	Timezone      string
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
		if bundle.Authz.File != "" {
			c.authzConfig = bundle.Authz
		}
		if bundle.Authz.Strict {
			c.authzStrict = true
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
		for _, detector := range bundle.Detectors {
			switch detector.Type {
			case "http":
				c.detectors = append(c.detectors, HTTPDetector{Definition: detector})
			case "dsl", "":
				if len(detector.Findings) > 0 || len(detector.Outputs) > 0 {
					c.detectors = append(c.detectors, DSLDetector{Definition: detector})
				}
			case "sensitive_endpoint":
				c.detectors = append(c.detectors, SensitiveEndpointDetector{})
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
