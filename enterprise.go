package tcpguard

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DetectorConfig is the normalized configuration passed to detector factories.
type DetectorConfig struct {
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

// DetectorDeps contains the enterprise runtime services a detector may use.
type DetectorDeps struct {
	Store          SecurityStore
	IncidentStore  IncidentStore
	ApprovalStore  ApprovalStore
	AuditStore     AuditStore
	DataSources    map[string]DataSource
	Lookups        []LookupDefinition
	SecretProvider func(*Context) []byte
	Metrics        MetricsRecorder
	Safety         PolicySafety
}

// DetectorFactory creates a configured detector from a BCL detector block.
type DetectorFactory interface {
	Name() string
	NewDetector(DetectorConfig, DetectorDeps) (Detector, error)
}

type DetectorFactoryFunc struct {
	FactoryName string
	Fn          func(DetectorConfig, DetectorDeps) (Detector, error)
}

func (f DetectorFactoryFunc) Name() string { return f.FactoryName }
func (f DetectorFactoryFunc) NewDetector(cfg DetectorConfig, deps DetectorDeps) (Detector, error) {
	return f.Fn(cfg, deps)
}

var detectorRegistry = struct {
	sync.RWMutex
	factories map[string]DetectorFactory
}{factories: map[string]DetectorFactory{}}

// RegisterDetectorFactory registers a process-wide detector factory. It is safe
// to call from init functions in optional detector modules.
func RegisterDetectorFactory(factory DetectorFactory) error {
	if factory == nil || strings.TrimSpace(factory.Name()) == "" {
		return errors.New("tcpguard: detector factory requires a name")
	}
	name := strings.ToLower(strings.TrimSpace(factory.Name()))
	detectorRegistry.Lock()
	detectorRegistry.factories[name] = factory
	detectorRegistry.Unlock()
	return nil
}

func init() {
	mustRegisterDetectorFactory("http", func(cfg DetectorConfig, _ DetectorDeps) (Detector, error) {
		return HTTPDetector{Definition: detectorDefinitionFromConfig(cfg)}, nil
	})
	mustRegisterDetectorFactory("dsl", func(cfg DetectorConfig, _ DetectorDeps) (Detector, error) {
		def := detectorDefinitionFromConfig(cfg)
		if len(def.Findings) == 0 && len(def.Outputs) == 0 {
			return nil, nil
		}
		return DSLDetector{Definition: def}, nil
	})
	mustRegisterDetectorFactory("sensitive_endpoint", func(cfg DetectorConfig, _ DetectorDeps) (Detector, error) {
		d := SensitiveEndpointDetector{}
		if v, ok := stringSliceField(cfg.Fields, "patterns"); ok {
			d.Patterns = v
		}
		return d, nil
	})
	mustRegisterDetectorFactory("abuse", func(cfg DetectorConfig, deps DetectorDeps) (Detector, error) {
		return abuseDetectorFromDefinition(detectorDefinitionFromConfig(cfg), deps.Store), nil
	})
	mustRegisterDetectorFactory("rate", func(cfg DetectorConfig, deps DetectorDeps) (Detector, error) {
		d := NewRateDetector(deps.Store)
		if v, ok := durationField(cfg.Fields, "window"); ok {
			d.Window = v
		}
		if v, ok := intField(cfg.Fields, "ip_limit"); ok {
			d.IPLimit = v
		}
		if v, ok := intField(cfg.Fields, "user_limit"); ok {
			d.UserLimit = v
		}
		if v, ok := intField(cfg.Fields, "tenant_limit"); ok {
			d.TenantLimit = v
		}
		if v, ok := intField(cfg.Fields, "session_limit"); ok {
			d.SessionLimit = v
		}
		if v, ok := intField(cfg.Fields, "endpoint_limit"); ok {
			d.EndpointLimit = v
		}
		if v, ok := intField(cfg.Fields, "ip_user_limit"); ok {
			d.IPUserLimit = v
		}
		if v, ok := intField(cfg.Fields, "tenant_endpoint_limit"); ok {
			d.TenantEndpointLimit = v
		}
		if v, ok := stringField(cfg.Fields, "algorithm"); ok {
			d.Algorithm = RateAlgorithm(v)
		}
		return d, nil
	})
	mustRegisterDetectorFactory("replay", func(cfg DetectorConfig, deps DetectorDeps) (Detector, error) {
		d := NewReplayDetector(deps.Store, deps.SecretProvider)
		if v, ok := durationField(cfg.Fields, "clock_skew"); ok {
			d.ClockSkew = v
		}
		if v, ok := durationField(cfg.Fields, "nonce_ttl"); ok {
			d.NonceTTL = v
		}
		return d, nil
	})
	mustRegisterDetectorFactory("header_anomaly", func(_ DetectorConfig, _ DetectorDeps) (Detector, error) { return HeaderAnomalyDetector{}, nil })
	mustRegisterDetectorFactory("session_drift", func(_ DetectorConfig, _ DetectorDeps) (Detector, error) { return SessionDriftDetector{}, nil })
	mustRegisterDetectorFactory("business_anomaly", func(_ DetectorConfig, _ DetectorDeps) (Detector, error) { return BusinessAnomalyDetector{}, nil })
}

func mustRegisterDetectorFactory(name string, fn func(DetectorConfig, DetectorDeps) (Detector, error)) {
	if err := RegisterDetectorFactory(DetectorFactoryFunc{FactoryName: name, Fn: fn}); err != nil {
		panic(err)
	}
}

func newDetectorFromDefinition(def DetectorDefinition, deps DetectorDeps) (Detector, bool, error) {
	typ := strings.ToLower(strings.TrimSpace(def.Type))
	if typ == "" {
		typ = "dsl"
	}
	detectorRegistry.RLock()
	factory := detectorRegistry.factories[typ]
	detectorRegistry.RUnlock()
	if factory == nil {
		return nil, false, nil
	}
	d, err := factory.NewDetector(detectorConfigFromDefinition(def), deps)
	return d, true, err
}

func detectorConfigFromDefinition(def DetectorDefinition) DetectorConfig {
	return DetectorConfig{ID: def.ID, Type: def.Type, Input: def.Input, Endpoint: def.Endpoint, Method: def.Method, Timeout: def.Timeout, Fallback: def.Fallback, Fields: def.Fields, Findings: def.Findings, Outputs: def.Outputs}
}

func detectorDefinitionFromConfig(cfg DetectorConfig) DetectorDefinition {
	return DetectorDefinition{ID: cfg.ID, Type: cfg.Type, Input: cfg.Input, Endpoint: cfg.Endpoint, Method: cfg.Method, Timeout: cfg.Timeout, Fallback: cfg.Fallback, Fields: cfg.Fields, Findings: cfg.Findings, Outputs: cfg.Outputs}
}

func stringField(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}

func stringSliceField(m map[string]any, key string) ([]string, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...), true
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out, len(out) > 0
	case string:
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out, len(out) > 0
	default:
		return nil, false
	}
}

// PolicyLintIssue is a deterministic policy authoring problem reported by LintBundle.
type PolicyLintIssue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Target   string `json:"target,omitempty"`
	Message  string `json:"message"`
}

type PolicyLintReport struct {
	Valid  bool              `json:"valid"`
	Issues []PolicyLintIssue `json:"issues"`
}

// LintBundle performs enterprise policy quality checks beyond syntax validation.
func LintBundle(bundle Bundle) PolicyLintReport {
	var issues []PolicyLintIssue
	add := func(sev, code, target, msg string) {
		issues = append(issues, PolicyLintIssue{Severity: sev, Code: code, Target: target, Message: msg})
	}
	ids := map[string]bool{}
	actionIDs := map[string]ActionDefinition{}
	for _, a := range bundle.Actions {
		actionIDs[a.ID] = a
	}
	usedActions := map[string]bool{}
	for _, r := range bundle.Rules {
		if strings.TrimSpace(r.ID) == "" {
			add("error", "rule_id_missing", "rule", "rule id is required")
			continue
		}
		if ids[r.ID] {
			add("error", "duplicate_rule_id", r.ID, "rule id is duplicated")
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Name) == "" {
			add("warning", "rule_name_missing", r.ID, "rule should have a human-readable name")
		}
		if r.Status == "" {
			add("warning", "rule_status_missing", r.ID, "rule should declare status")
		}
		if len(r.Triggers) == 0 && r.Sequence == nil {
			add("warning", "rule_trigger_missing", r.ID, "rule has no trigger and will not match")
		}
		if r.Condition == "" && r.Sequence == nil {
			add("warning", "rule_condition_missing", r.ID, "rule has no condition; ensure this is intentional")
		}
		if len(r.Severity) == 0 {
			add("warning", "severity_missing", r.ID, "rule should declare severity mapping")
		}
		if len(r.Actions) == 0 {
			add("warning", "actions_missing", r.ID, "rule should define response actions")
		}
		if len(r.Scope.Paths) == 1 && r.Scope.Paths[0] == "*" {
			add("warning", "broad_scope", r.ID, "wildcard path scope should be avoided for enforcing rules")
		}
		for _, refs := range r.Actions {
			for _, ref := range refs {
				usedActions[ref.ID] = true
				if _, ok := actionIDs[ref.ID]; !ok && !builtinActionID(ref.ID) {
					add("error", "unknown_action", r.ID, "rule references undefined action "+ref.ID)
				}
			}
		}
		if bundle.Authz.Strict && strings.TrimSpace(r.AuthzPolicy) == "" {
			add("error", "authz_policy_missing", r.ID, "strict authz requires rule authz_policy")
		}
	}
	for _, a := range bundle.Actions {
		if !usedActions[a.ID] {
			add("info", "unused_action", a.ID, "action is defined but not referenced by any rule")
		}
		if strings.TrimSpace(a.Type) == "webhook" && strings.TrimSpace(firstNonEmpty(a.Endpoint, a.Request.Endpoint)) == "" {
			add("error", "webhook_endpoint_missing", a.ID, "webhook action requires endpoint")
		}
	}
	ds := map[string]bool{}
	for _, d := range bundle.DataSources {
		ds[d.ID] = true
	}
	for _, l := range bundle.Lookups {
		if !ds[l.Source] {
			add("error", "lookup_datasource_missing", l.ID, "lookup references unknown datasource "+l.Source)
		}
		if l.Fallback.Policy == "" {
			add("warning", "lookup_fallback_missing", l.ID, "lookup should explicitly define fallback policy")
		}
	}
	for _, d := range bundle.Detectors {
		typ := strings.ToLower(strings.TrimSpace(d.Type))
		if typ == "" {
			typ = "dsl"
		}
		detectorRegistry.RLock()
		_, ok := detectorRegistry.factories[typ]
		detectorRegistry.RUnlock()
		if !ok {
			add("error", "unknown_detector", d.ID, "no detector factory registered for type "+typ)
		}
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity == issues[j].Severity {
			return issues[i].Code < issues[j].Code
		}
		rank := map[string]int{"error": 0, "warning": 1, "info": 2}
		return rank[issues[i].Severity] < rank[issues[j].Severity]
	})
	valid := true
	for _, issue := range issues {
		if issue.Severity == "error" {
			valid = false
			break
		}
	}
	return PolicyLintReport{Valid: valid, Issues: issues}
}

func builtinActionID(id string) bool {
	switch id {
	case "allow", "monitor", "add_risk_header", "throttle", "delay", "tarpit", "block", "captcha_challenge", "mfa_challenge", "reauthenticate", "revoke_session", "revoke_all_sessions", "disable_api_key", "lock_user", "ban_ip", "ban_asn", "block_country", "audit", "create_incident", "escalate_incident", "notify_admin", "notify_user", "notify_soc", "webhook", "siem", "event_bus", "sql", "command":
		return true
	default:
		return false
	}
}

// DecisionTrace is a structured, SOC-friendly explanation attached to decisions.
type DecisionTrace struct {
	Summary            string            `json:"summary"`
	RiskContributors   []RiskContributor `json:"risk_contributors,omitempty"`
	RecommendedActions []string          `json:"recommended_actions,omitempty"`
	Policy             map[string]any    `json:"policy,omitempty"`
}

type RiskContributor struct {
	Source  string  `json:"source"`
	Risk    float64 `json:"risk"`
	Message string  `json:"message,omitempty"`
}

func buildDecisionTrace(decision Decision) *DecisionTrace {
	trace := &DecisionTrace{Summary: decision.Explanation, Policy: map[string]any{"version": decision.PolicyVersion, "config_hash": decision.ConfigHash}}
	if trace.Summary == "" {
		trace.Summary = fmt.Sprintf("%s decision with risk %.0f", decision.Effect, decision.Risk.Score)
	}
	for _, f := range decision.Findings {
		trace.RiskContributors = append(trace.RiskContributors, RiskContributor{Source: firstNonEmpty(f.ID, f.Type), Risk: f.Risk, Message: f.Message})
	}
	switch decision.Effect {
	case DecisionBlock:
		trace.RecommendedActions = []string{"review audit evidence", "check matched rules", "verify source IP, user, session, and API key", "open or update incident"}
	case DecisionChallenge:
		trace.RecommendedActions = []string{"step up authentication", "verify user intent", "review recent entity profile changes"}
	case DecisionThrottle:
		trace.RecommendedActions = []string{"inspect rate counters", "review client behavior", "consider tighter endpoint policy"}
	default:
		if decision.Risk.Score >= 50 {
			trace.RecommendedActions = []string{"monitor entity profile", "review findings if risk increases"}
		}
	}
	return trace
}
