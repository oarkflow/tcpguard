package tcpguard

import (
	"context"
	"net/http"
	"time"

	"github.com/oarkflow/condition"
)

type Mode string

const (
	Monitor Mode = "monitor"
	Shadow  Mode = "shadow"
	DryRun  Mode = "dry_run"
	Enforce Mode = "enforce"
)

type RateAlgorithm string

const (
	RateFixedWindow   RateAlgorithm = "fixed_window"
	RateSlidingWindow RateAlgorithm = "sliding_window"
	RateTokenBucket   RateAlgorithm = "token_bucket"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type DecisionEffect string

const (
	DecisionAllow     DecisionEffect = "allow"
	DecisionDeny      DecisionEffect = "deny"
	DecisionMonitor   DecisionEffect = "monitor"
	DecisionChallenge DecisionEffect = "challenge"
	DecisionThrottle  DecisionEffect = "throttle"
	DecisionBlock     DecisionEffect = "block"
	DecisionRevoke    DecisionEffect = "revoke"
	DecisionEscalate  DecisionEffect = "escalate"
)

type Context struct {
	Request  RequestContext     `json:"request,omitempty"`
	Network  NetworkContext     `json:"network,omitempty"`
	Identity IdentityContext    `json:"user,omitempty"`
	Session  SessionContext     `json:"session,omitempty"`
	Device   DeviceContext      `json:"device,omitempty"`
	Tenant   TenantContext      `json:"tenant,omitempty"`
	Business BusinessContext    `json:"business,omitempty"`
	Runtime  RuntimeContext     `json:"runtime,omitempty"`
	Security map[string]any     `json:"security,omitempty"`
	Rate     map[string]any     `json:"rate,omitempty"`
	Extra    condition.MapFacts `json:"extra,omitempty"`
	Facts    condition.MapFacts `json:"-"`
	Raw      *http.Request      `json:"-"`
	lookup   *LookupContext
}

type RequestContext struct {
	ID          string            `json:"id,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Query       map[string]string `json:"query,omitempty"`
	BodySize    int64             `json:"body_size,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Host        string            `json:"host,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Origin      string            `json:"origin,omitempty"`
	Referer     string            `json:"referer,omitempty"`
	Params      map[string]string `json:"params,omitempty"`
}

type NetworkContext struct {
	IP              string  `json:"ip,omitempty"`
	CountryCode     string  `json:"country_code,omitempty"`
	Country         string  `json:"country,omitempty"`
	CountryName     string  `json:"country_name,omitempty"`
	Region          string  `json:"region,omitempty"`
	City            string  `json:"city,omitempty"`
	ASN             string  `json:"asn,omitempty"`
	Latitude        float64 `json:"latitude,omitempty"`
	Longitude       float64 `json:"longitude,omitempty"`
	GeoFound        bool    `json:"geo_found,omitempty"`
	Proxy           bool    `json:"proxy,omitempty"`
	VPN             bool    `json:"vpn,omitempty"`
	Tor             bool    `json:"tor,omitempty"`
	Reputation      float64 `json:"reputation,omitempty"`
	IntelSource     string  `json:"intel_source,omitempty"`
	IntelMatchType  string  `json:"intel_match_type,omitempty"`
	IntelConfidence float64 `json:"intel_confidence,omitempty"`
	PreviousIP      string  `json:"previous_ip,omitempty"`
	PreviousCountry string  `json:"previous_country,omitempty"`
}

type IdentityContext struct {
	ID          string         `json:"id,omitempty"`
	Type        string         `json:"type,omitempty"`
	Role        string         `json:"role,omitempty"`
	Roles       []string       `json:"roles,omitempty"`
	Groups      []string       `json:"groups,omitempty"`
	Tenant      string         `json:"tenant,omitempty"`
	Permissions []string       `json:"permissions,omitempty"`
	AuthMethod  string         `json:"auth_method,omitempty"`
	Attrs       map[string]any `json:"attrs,omitempty"`
}

type SessionContext struct {
	ID               string    `json:"id,omitempty"`
	DeviceID         string    `json:"device_id,omitempty"`
	UserAgent        string    `json:"user_agent,omitempty"`
	Fingerprint      string    `json:"fingerprint,omitempty"`
	PreviousIP       string    `json:"previous_ip,omitempty"`
	PreviousCountry  string    `json:"previous_country,omitempty"`
	LastSeenAt       time.Time `json:"last_seen_at,omitempty"`
	LastSeenAge      string    `json:"last_seen_age,omitempty"`
	NewDevice        bool      `json:"new_device,omitempty"`
	CountryChanged   bool      `json:"country_changed,omitempty"`
	ASNChanged       bool      `json:"asn_changed,omitempty"`
	DeviceChanged    bool      `json:"device_changed,omitempty"`
	UserAgentChanged bool      `json:"user_agent_changed,omitempty"`
}

type DeviceContext struct {
	ID          string `json:"id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	New         bool   `json:"new,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
}

type TenantContext struct {
	ID          string         `json:"id,omitempty"`
	Plan        string         `json:"plan,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type BusinessContext struct {
	Action        string  `json:"action,omitempty"`
	Entity        string  `json:"entity,omitempty"`
	Amount        float64 `json:"amount,omitempty"`
	Workflow      string  `json:"workflow,omitempty"`
	ApprovalLevel string  `json:"approval_level,omitempty"`
	Sensitivity   string  `json:"sensitivity,omitempty"`
	OutsideHours  bool    `json:"outside_hours,omitempty"`
	Holiday       bool    `json:"holiday,omitempty"`
}

type RuntimeContext struct {
	Timestamp     time.Time `json:"timestamp,omitempty"`
	BusinessHours bool      `json:"business_hours,omitempty"`
	Holiday       bool      `json:"holiday,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	ConfigHash    string    `json:"config_hash,omitempty"`
}

type Event struct {
	Type      string             `json:"type"`
	Source    string             `json:"source,omitempty"`
	At        time.Time          `json:"at,omitempty"`
	Fields    condition.MapFacts `json:"fields,omitempty"`
	RequestID string             `json:"request_id,omitempty"`
}

type Finding struct {
	ID               string              `json:"id"`
	Type             string              `json:"type,omitempty"`
	Severity         Severity            `json:"severity,omitempty"`
	Confidence       float64             `json:"confidence,omitempty"`
	Risk             float64             `json:"risk,omitempty"`
	Message          string              `json:"message,omitempty"`
	Fields           map[string]any      `json:"fields,omitempty"`
	STRIDE           []string            `json:"stride,omitempty"`
	MITRE            []string            `json:"mitre,omitempty"`
	ThreatCategories map[string][]string `json:"threat_categories,omitempty"`
}

type Risk struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence,omitempty"`
}

type Decision struct {
	Effect        DecisionEffect   `json:"effect"`
	Allowed       bool             `json:"allowed"`
	Risk          Risk             `json:"risk"`
	Severity      Severity         `json:"severity"`
	Findings      []Finding        `json:"findings,omitempty"`
	Evidence      []Evidence       `json:"evidence,omitempty"`
	MatchedRules  []string         `json:"matched_rules,omitempty"`
	Actions       []ActionResult   `json:"actions,omitempty"`
	Incidents     []Incident       `json:"incidents,omitempty"`
	Explanation   string           `json:"explanation,omitempty"`
	PolicyVersion string           `json:"policy_version,omitempty"`
	ConfigHash    string           `json:"config_hash,omitempty"`
	Audit         AuditRecord      `json:"audit"`
	AuditEnvelope *AuditEnvelope   `json:"audit_envelope,omitempty"`
	Profiles      []EntityProfile  `json:"profiles,omitempty"`
	Approvals     []ApprovalRecord `json:"approvals,omitempty"`
	Trace         *DecisionTrace   `json:"trace,omitempty"`
}

type DecisionResponse struct {
	Status  int
	Headers map[string]string
	Body    any
}

type DecisionResponseRenderer func(*Context, Decision) DecisionResponse

type MetricsRecorder interface {
	RecordDecision(context.Context, *Context, Decision, time.Duration)
	RecordDetector(context.Context, string, int, error, time.Duration)
	RecordAction(context.Context, *Context, Decision, ActionResult, time.Duration)
	RecordReload(context.Context, bool, time.Duration)
}

type Evidence struct {
	Type    string         `json:"type"`
	ID      string         `json:"id,omitempty"`
	Message string         `json:"message,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type ActionResult struct {
	ID     string         `json:"id"`
	Type   string         `json:"type,omitempty"`
	Status string         `json:"status"`
	Error  string         `json:"error,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	At     time.Time      `json:"at,omitempty"`
}

type Incident struct {
	ID        string    `json:"id"`
	Severity  Severity  `json:"severity"`
	Status    string    `json:"status"`
	Summary   string    `json:"summary,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditRecord struct {
	RequestID          string         `json:"request_id,omitempty"`
	Event              string         `json:"event,omitempty"`
	Decision           string         `json:"decision,omitempty"`
	RiskScore          float64        `json:"risk_score,omitempty"`
	Severity           Severity       `json:"severity,omitempty"`
	MatchedRules       []string       `json:"matched_rules,omitempty"`
	Findings           []string       `json:"findings,omitempty"`
	Evidence           []string       `json:"evidence,omitempty"`
	ActionResults      []ActionResult `json:"action_results,omitempty"`
	ApprovalIDs        []string       `json:"approval_ids,omitempty"`
	Explanation        string         `json:"explanation,omitempty"`
	RequestFingerprint string         `json:"request_fingerprint,omitempty"`
	PolicyVersion      string         `json:"policy_version,omitempty"`
	ConfigHash         string         `json:"config_hash,omitempty"`
	At                 time.Time      `json:"at"`
}

type AuditEnvelope struct {
	ID           string      `json:"id"`
	Sequence     uint64      `json:"sequence"`
	Timestamp    string      `json:"timestamp"`
	PreviousHash string      `json:"previous_hash,omitempty"`
	PayloadHash  string      `json:"payload_hash"`
	ChainHash    string      `json:"chain_hash"`
	Signature    string      `json:"signature,omitempty"`
	Record       AuditRecord `json:"record"`
}

type EntityProfile struct {
	Entity     string    `json:"entity"`
	ID         string    `json:"id"`
	RiskScore  float64   `json:"risk_score"`
	Confidence float64   `json:"confidence,omitempty"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type Scope struct {
	Tenants []string `json:"tenants,omitempty"`
	Roles   []string `json:"roles,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

type Cooldown struct {
	Key      string        `json:"key,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
}

type Rollout struct {
	Mode  string  `json:"mode,omitempty"`
	Value float64 `json:"value,omitempty"`
}

type Approval struct {
	Required  bool     `json:"required,omitempty"`
	Approvers []string `json:"approvers,omitempty"`
}

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
)

type ApprovalRecord struct {
	ID          string         `json:"id"`
	Status      ApprovalStatus `json:"status"`
	RuleID      string         `json:"rule_id"`
	RequestID   string         `json:"request_id,omitempty"`
	ActionIDs   []string       `json:"action_ids,omitempty"`
	Approvers   []string       `json:"approvers,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	RequestedAt time.Time      `json:"requested_at"`
	DecidedAt   time.Time      `json:"decided_at,omitempty"`
	DecidedBy   string         `json:"decided_by,omitempty"`
}

type ThreatMapping struct {
	STRIDE []string `json:"stride,omitempty"`
	MITRE  []string `json:"mitre,omitempty"`
}

type RuleStatus string

const (
	RuleDraft      RuleStatus = "draft"
	RuleShadow     RuleStatus = "shadow"
	RuleTesting    RuleStatus = "testing"
	RuleActive     RuleStatus = "active"
	RulePaused     RuleStatus = "paused"
	RuleDeprecated RuleStatus = "deprecated"
	RuleArchived   RuleStatus = "archived"
)

type Rule struct {
	ID             string
	Name           string
	Status         RuleStatus
	Priority       int
	Version        int
	Owner          string
	Scope          Scope
	Triggers       []string
	Sequence       *SequenceTrigger
	Condition      string
	Risk           RiskSpec
	Severity       []SeverityRule
	Actions        map[Severity][]ActionRef
	Cooldown       Cooldown
	Rollout        Rollout
	Approval       Approval
	Threat         ThreatMapping
	AuthzPolicy    string
	Explain        bool
	compiled       *condition.Expression
	scopePaths     []pathPattern
	riskAdders     []compiledRiskAdder
	severityExpr   []compiledSeverityRule
	needsRiskFacts bool
}

type RiskSpec struct {
	Base    float64
	Max     float64
	Decay   time.Duration
	Profile []string
	Adders  []RiskAdder
}

type RiskAdder struct {
	Value     float64
	Field     string
	Scale     float64
	Condition string
}

type SeverityRule struct {
	Severity  Severity
	Condition string
}

type ActionRef struct {
	ID     string
	Args   []string
	Fields map[string]any
}

type ActionDefinition struct {
	ID      string
	Type    string
	Request ActionRequest
	// Endpoint, Method, Headers, and BodyTemplate are retained as convenient
	// top-level aliases for simple actions and backward compatibility.
	Endpoint        string
	Method          string
	Headers         map[string]string
	BodyTemplate    string
	Provider        string
	Subject         string
	Timeout         time.Duration
	Retry           RetryPolicy
	Fields          map[string]any
	SuccessCodes    []string
	RetryOnCodes    []string
	Idempotency     IdempotencyPolicy
	AllowPrivateURL bool
}

type ActionRequest struct {
	Endpoint     string
	Method       string
	Headers      map[string]string
	BodyTemplate string
	Body         map[string]any
	Include      map[string]string
	Fields       map[string]any
}

type Placeholder string

type EnvRef string
type ContextRef string
type SessionRef string

type RetryPolicy struct {
	Attempts int
	Backoff  string
	Jitter   bool
}

type IdempotencyPolicy struct {
	Header string
	Key    string
}

type SequenceTrigger struct {
	Within time.Duration
	Steps  []SequenceStep
}

type SequenceStep struct {
	Event     string
	Count     int
	Condition string
}

type ContextBuilder interface {
	BuildHTTP(context.Context, *http.Request) (*Context, error)
}

type Enricher interface {
	ID() string
	Enrich(context.Context, *Context) error
}

type IntelFeed interface {
	ID() string
	Enrich(context.Context, *Context) error
}

type Detector interface {
	ID() string
	Detect(context.Context, *Context, Event) ([]Finding, error)
}

type TriggerEngine interface {
	Match(context.Context, *Context, Event, *Rule) (bool, error)
}

type RuleEngine interface {
	Evaluate(context.Context, *Context, Event, []Finding) (Decision, error)
}

type RiskScorer interface {
	Score(context.Context, *Context, *Rule, []Finding) (Risk, error)
}

type PolicyEngine interface {
	Decide(context.Context, *Context, Event, []RuleResult) Decision
}

type ActionExecutor interface {
	Execute(context.Context, *Context, Decision, ActionRef) ActionResult
}

type SecurityStore interface {
	Get(context.Context, string) ([]byte, bool, error)
	Set(context.Context, string, []byte, time.Duration) error
	Delete(context.Context, string) error
	Incr(context.Context, string, time.Duration) (int64, error)
}

type DataSource interface {
	ID() string
	Lookup(context.Context, LookupRequest) (LookupResult, error)
}

type LookupRequest struct {
	Source string
	Key    string
	Value  any
	Query  string
	Params map[string]any
	Fields []string
}

type LookupResult struct {
	Found  bool
	Value  any
	Fields map[string]any
}

type DataSourceRegistry interface {
	RegisterDataSource(DataSource)
}

type IncidentStore interface {
	SaveIncident(context.Context, Incident) error
	ListIncidents(context.Context) ([]Incident, error)
}

type AuditStore interface {
	SaveAuditEnvelope(context.Context, AuditRecord) (AuditEnvelope, error)
	ListAuditEnvelopes(context.Context) ([]AuditEnvelope, error)
	GetAuditEnvelope(context.Context, string) (AuditEnvelope, bool, error)
}

type ApprovalStore interface {
	SaveApproval(context.Context, ApprovalRecord) error
	GetApproval(context.Context, string) (ApprovalRecord, bool, error)
	ListApprovals(context.Context, ApprovalStatus) ([]ApprovalRecord, error)
	UpdateApproval(context.Context, ApprovalRecord) error
}

type PluginRegistry interface {
	RegisterDetector(Detector)
	RegisterEnricher(Enricher)
	RegisterAction(string, ActionExecutor)
}

type RuleResult struct {
	Rule     *Rule
	Risk     Risk
	Severity Severity
	Findings []Finding
	Actions  []ActionRef
	Authz    *AuthzEvidence
}

type compiledRiskAdder struct {
	spec RiskAdder
	expr *condition.Expression
}

type compiledSeverityRule struct {
	spec           SeverityRule
	expr           *condition.Expression
	riskScoreOp    string
	riskScoreValue float64
}
