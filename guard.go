package tcpguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/condition"
)

type Option func(*config)

type config struct {
	mode             Mode
	defaultEffect    DecisionEffect
	policyVersion    string
	configHash       string
	builder          ContextBuilder
	store            SecurityStore
	incidentStore    IncidentStore
	approvalStore    ApprovalStore
	auditStore       AuditStore
	detectors        []Detector
	enrichers        []Enricher
	intel            []IntelFeed
	derived          []DerivedTrigger
	rules            []Rule
	actions          map[string]ActionDefinition
	actionHandlers   map[string]ActionExecutor
	secretProvider   func(*Context) []byte
	safety           PolicySafety
	threatModels     []ThreatModelDefinition
	datasourceDefs   []DataSourceDefinition
	datasources      map[string]DataSource
	lookups          []LookupDefinition
	noDefaults       bool
	rateAlgorithm    RateAlgorithm
	fastRuntime      bool
	fastRuntimeSet   bool
	baselines        []BaselineDefinition
	disableAudit     bool
	disableProfiles  bool
	responseRenderer DecisionResponseRenderer
	metrics          MetricsRecorder
	authzProvider    AuthzProvider
	authzConfig      AuthzConfig
	authzStrict      bool
}

type Guard struct {
	mu               sync.RWMutex
	snapshot         atomic.Pointer[runtimeSnapshot]
	mode             Mode
	defaultEffect    DecisionEffect
	policyVersion    string
	configHash       string
	builder          ContextBuilder
	store            SecurityStore
	incidentStore    IncidentStore
	approvalStore    ApprovalStore
	auditStore       AuditStore
	detectors        []Detector
	enrichers        []Enricher
	intel            []IntelFeed
	derived          []DerivedTrigger
	rules            []Rule
	actions          map[string]ActionDefinition
	actionHandlers   map[string]ActionExecutor
	safety           PolicySafety
	threatModels     []ThreatModelDefinition
	datasources      map[string]DataSource
	lookups          []LookupDefinition
	auditEnabled     bool
	profilesEnabled  bool
	fastRuntime      bool
	responseRenderer DecisionResponseRenderer
	metrics          MetricsRecorder
	authzProvider    AuthzProvider
	authzConfig      AuthzConfig
	authzStrict      bool
}

func New(opts ...Option) (*Guard, error) {
	cfg := config{
		mode:           Monitor,
		defaultEffect:  DecisionAllow,
		store:          NewMemoryStore(),
		actions:        map[string]ActionDefinition{},
		actionHandlers: map[string]ActionExecutor{},
		datasources:    map[string]DataSource{},
		safety:         DefaultPolicySafety(),
		fastRuntime:    true,
		authzStrict:    false,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.builder == nil {
		cfg.builder = HTTPContextBuilder{TrustedProxyHeaders: false}
	}
	if cfg.incidentStore == nil {
		if s, ok := cfg.store.(IncidentStore); ok {
			cfg.incidentStore = s
		}
	}
	if cfg.approvalStore == nil {
		if s, ok := cfg.store.(ApprovalStore); ok {
			cfg.approvalStore = s
		}
	}
	if cfg.auditStore == nil {
		if s, ok := cfg.store.(AuditStore); ok {
			cfg.auditStore = s
		}
	}
	if err := configureDataSources(&cfg); err != nil {
		return nil, err
	}
	if err := validateActionDefinitions(cfg.actions, cfg.safety); err != nil {
		return nil, err
	}
	for _, actionType := range []string{"allow", "monitor", "add_risk_header", "throttle", "delay", "tarpit", "block", "captcha_challenge", "mfa_challenge", "reauthenticate", "revoke_session", "revoke_all_sessions", "disable_api_key", "lock_user", "ban_ip", "ban_asn", "block_country", "audit", "create_incident", "escalate_incident", "notify_admin", "notify_user", "notify_soc", "webhook", "siem", "event_bus", "sql", "command"} {
		if cfg.actionHandlers[actionType] == nil {
			cfg.actionHandlers[actionType] = BuiltinActionExecutor{Store: cfg.store, Incidents: cfg.incidentStore, Definition: cfg.actions}
		}
	}
	for _, baseline := range cfg.baselines {
		cfg.detectors = append(cfg.detectors, BaselineDetector{Definition: baseline, Store: cfg.store})
	}
	if !cfg.noDefaults {
		cfg.detectors = append(DefaultDetectorsWithRateAlgorithm(cfg.store, cfg.secretProvider, cfg.rateAlgorithm), cfg.detectors...)
	}
	derived := append([]DerivedTrigger(nil), cfg.derived...)
	for i := range derived {
		if derived[i].Condition == "" {
			continue
		}
		expr, err := condition.Compile(normalizeCondition(derived[i].Condition))
		if err != nil {
			return nil, fmt.Errorf("tcpguard: compile derived trigger %s: %w", derived[i].ID, err)
		}
		derived[i].compiled = expr
	}
	rules := append([]Rule(nil), cfg.rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	for i := range rules {
		if rules[i].Status == "" {
			rules[i].Status = RuleActive
		}
		if err := compileRule(&rules[i]); err != nil {
			return nil, err
		}
	}
	if err := validateRulesAgainstSafety(rules, cfg.actions, cfg.safety); err != nil {
		return nil, err
	}
	if err := validateLookupsAgainstSafety(cfg.lookups, cfg.datasources, cfg.safety); err != nil {
		return nil, err
	}
	if cfg.authzStrict {
		if cfg.authzProvider == nil && strings.TrimSpace(cfg.authzConfig.File) == "" {
			return nil, errors.New("tcpguard: strict authz requires authz provider or authz config file")
		}
	}
	if cfg.authzProvider == nil && strings.TrimSpace(cfg.authzConfig.File) != "" {
		provider, err := NewOarkflowAuthzProviderFromFile(cfg.authzConfig.File)
		if err != nil {
			return nil, err
		}
		cfg.authzProvider = provider
	}
	if cfg.configHash == "" {
		cfg.configHash = digestRules(rules, cfg.actions)
	}
	guard := &Guard{
		mode:             cfg.mode,
		defaultEffect:    cfg.defaultEffect,
		policyVersion:    cfg.policyVersion,
		configHash:       cfg.configHash,
		builder:          cfg.builder,
		store:            cfg.store,
		incidentStore:    cfg.incidentStore,
		approvalStore:    cfg.approvalStore,
		auditStore:       cfg.auditStore,
		detectors:        cfg.detectors,
		enrichers:        cfg.enrichers,
		intel:            cfg.intel,
		derived:          derived,
		rules:            rules,
		actions:          cfg.actions,
		actionHandlers:   cfg.actionHandlers,
		safety:           cfg.safety,
		threatModels:     cfg.threatModels,
		datasources:      copyDataSources(cfg.datasources),
		lookups:          append([]LookupDefinition(nil), cfg.lookups...),
		auditEnabled:     !cfg.disableAudit,
		profilesEnabled:  !cfg.disableProfiles,
		fastRuntime:      cfg.fastRuntime || !cfg.fastRuntimeSet,
		responseRenderer: cfg.responseRenderer,
		metrics:          cfg.metrics,
		authzProvider:    cfg.authzProvider,
		authzConfig:      cfg.authzConfig,
		authzStrict:      cfg.authzStrict,
	}
	guard.publishSnapshotLocked()
	return guard, nil
}

func WithMode(mode Mode) Option { return func(c *config) { c.mode = mode } }
func WithDefaultEffect(effect DecisionEffect) Option {
	return func(c *config) { c.defaultEffect = effect }
}
func WithContextBuilder(builder ContextBuilder) Option {
	return func(c *config) { c.builder = builder }
}
func WithStore(store SecurityStore) Option { return func(c *config) { c.store = store } }
func WithIncidentStore(store IncidentStore) Option {
	return func(c *config) { c.incidentStore = store }
}
func WithApprovalStore(store ApprovalStore) Option {
	return func(c *config) { c.approvalStore = store }
}
func WithAuditStore(store AuditStore) Option {
	return func(c *config) { c.auditStore = store }
}
func WithDetector(detector Detector) Option {
	return func(c *config) { c.detectors = append(c.detectors, detector) }
}
func WithoutDefaultDetectors() Option { return func(c *config) { c.noDefaults = true } }
func WithEnricher(enricher Enricher) Option {
	return func(c *config) { c.enrichers = append(c.enrichers, enricher) }
}
func WithIntel(feed IntelFeed) Option { return func(c *config) { c.intel = append(c.intel, feed) } }
func WithRule(rule Rule) Option       { return func(c *config) { c.rules = append(c.rules, rule) } }
func WithRules(rules ...Rule) Option {
	return func(c *config) { c.rules = append(c.rules, rules...) }
}
func WithAction(def ActionDefinition) Option {
	return func(c *config) {
		if c.actions == nil {
			c.actions = map[string]ActionDefinition{}
		}
		c.actions[def.ID] = def
	}
}
func WithActionExecutor(actionType string, executor ActionExecutor) Option {
	return func(c *config) {
		if c.actionHandlers == nil {
			c.actionHandlers = map[string]ActionExecutor{}
		}
		c.actionHandlers[actionType] = executor
	}
}
func WithHMACSecretProvider(fn func(*Context) []byte) Option {
	return func(c *config) { c.secretProvider = fn }
}
func WithPolicyVersion(version string) Option {
	return func(c *config) { c.policyVersion = version }
}
func WithSafety(safety PolicySafety) Option {
	return func(c *config) { c.safety = mergePolicySafety(c.safety, safety) }
}
func WithDataSource(source DataSource) Option {
	return func(c *config) {
		if source == nil || source.ID() == "" {
			return
		}
		if c.datasources == nil {
			c.datasources = map[string]DataSource{}
		}
		c.datasources[source.ID()] = source
	}
}
func WithSQLDataSource(id string, db *sql.DB) Option {
	return WithDataSource(SQLDataSource{SourceID: id, DB: db})
}
func WithoutAudit() Option          { return func(c *config) { c.disableAudit = true } }
func WithoutEntityProfiles() Option { return func(c *config) { c.disableProfiles = true } }
func WithRateAlgorithm(algorithm RateAlgorithm) Option {
	return func(c *config) { c.rateAlgorithm = algorithm }
}
func WithFastRuntime(enabled bool) Option {
	return func(c *config) {
		c.fastRuntime = enabled
		c.fastRuntimeSet = true
	}
}
func WithResponseRenderer(renderer DecisionResponseRenderer) Option {
	return func(c *config) { c.responseRenderer = renderer }
}
func WithMetrics(recorder MetricsRecorder) Option {
	return func(c *config) { c.metrics = recorder }
}
func WithAuthzProvider(provider AuthzProvider) Option {
	return func(c *config) { c.authzProvider = provider }
}
func WithAuthzConfig(authzCfg AuthzConfig) Option {
	return func(c *config) { c.authzConfig = authzCfg }
}
func WithAuthzStrict(strict bool) Option {
	return func(c *config) { c.authzStrict = strict }
}

func (g *Guard) Evaluate(ctx context.Context, event Event, sec *Context) (decision Decision) {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.RLock()
	metrics := g.metrics
	g.mu.RUnlock()
	if metrics != nil {
		defer func() {
			metrics.RecordDecision(ctx, sec, decision, time.Since(started))
		}()
	}
	snap := g.snapshot.Load()
	if snap == nil {
		g.mu.RLock()
		snap = newRuntimeSnapshot(g)
		g.mu.RUnlock()
	}
	if sec == nil {
		sec = &Context{Security: map[string]any{}, Rate: map[string]any{}, Extra: condition.MapFacts{}}
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	if event.Type == "" {
		event.Type = "request.received"
	}
	sec.Runtime.PolicyVersion = snap.policyVersion
	sec.Runtime.ConfigHash = snap.configHash
	if snap.fastNoop {
		if blocked, finding := g.blockedByState(ctx, sec); blocked {
			decision = Decision{
				Effect:        DecisionBlock,
				Allowed:       false,
				Risk:          Risk{Score: 100, Confidence: 1},
				Severity:      SeverityCritical,
				Findings:      []Finding{finding},
				Evidence:      []Evidence{{Type: "state", ID: finding.ID, Message: finding.Message}},
				Explanation:   buildStateBlockExplanation(sec, finding),
				PolicyVersion: snap.policyVersion,
				ConfigHash:    snap.configHash,
			}
			decision.Audit = AuditRecord{RequestID: sec.Request.ID, Event: event.Type, Decision: string(decision.Effect), RiskScore: decision.Risk.Score, Severity: decision.Severity, Findings: findingIDs(decision.Findings), PolicyVersion: snap.policyVersion, ConfigHash: snap.configHash, At: time.Now().UTC()}
			g.persistAudit(ctx, sec, &decision)
			return decision
		}
		decision = decide(snap.mode, snap.defaultEffect, sec, event, nil, nil)
		decision.PolicyVersion = snap.policyVersion
		decision.ConfigHash = snap.configHash
		if snap.auditEnabled {
			decision.Audit = AuditRecord{RequestID: sec.Request.ID, Event: event.Type, Decision: string(decision.Effect), RiskScore: decision.Risk.Score, Severity: decision.Severity, Explanation: decision.Explanation, RequestFingerprint: requestFingerprint(sec), PolicyVersion: snap.policyVersion, ConfigHash: snap.configHash, At: time.Now().UTC()}
			g.persistAudit(ctx, sec, &decision)
		}
		return decision
	}
	if snap.needsFacts && sec.Extra == nil {
		sec.Extra = condition.MapFacts{}
	}
	if snap.needsFacts {
		sec.rebuildFacts()
	}
	if snap.needsLookup {
		if sec.Extra == nil {
			sec.Extra = condition.MapFacts{}
		}
		if sec.Facts == nil {
			sec.rebuildFacts()
		}
		sec.lookup = NewLookupContext(sec, snap.datasources, snap.lookups, snap.safety)
		setFact(sec.Facts, "__tcpguard_lookup_context", sec.lookup)
		setFact(sec.Extra, "__tcpguard_lookup_context", sec.lookup)
	}
	for _, enricher := range snap.enrichers {
		_ = enricher.Enrich(ctx, sec)
	}
	for _, feed := range snap.intel {
		_ = feed.Enrich(ctx, sec)
	}
	if snap.needsFacts && (len(snap.enrichers) > 0 || len(snap.intel) > 0) {
		sec.rebuildFacts()
		if sec.lookup != nil {
			setFact(sec.Facts, "__tcpguard_lookup_context", sec.lookup)
			setFact(sec.Extra, "__tcpguard_lookup_context", sec.lookup)
		}
	}
	if snap.needsLookup {
		preloadCandidates := snap.ruleIndex.candidatesForIndexed([]string{event.Type}, sec, snap.rules, snap.indexEnabled)
		g.runPreloadLookups(ctx, sec, snap, preloadCandidates)
	}
	if blocked, finding := g.blockedByState(ctx, sec); blocked {
		decision = Decision{
			Effect:      DecisionBlock,
			Allowed:     false,
			Risk:        Risk{Score: 100, Confidence: 1},
			Severity:    SeverityCritical,
			Findings:    []Finding{finding},
			Evidence:    []Evidence{{Type: "state", ID: finding.ID, Message: finding.Message}},
			Explanation: buildStateBlockExplanation(sec, finding),
		}
		decision.Audit = AuditRecord{RequestID: sec.Request.ID, Event: event.Type, Decision: string(decision.Effect), RiskScore: decision.Risk.Score, Severity: decision.Severity, Findings: findingIDs(decision.Findings), PolicyVersion: snap.policyVersion, ConfigHash: snap.configHash, At: time.Now().UTC()}
		g.persistAudit(ctx, sec, &decision)
		return decision
	}
	var findings []Finding
	for _, detector := range snap.detectors {
		if !detectorShouldRun(detector, sec, event) {
			continue
		}
		detectorStarted := time.Now()
		dctx := ctx
		cancel := func() {}
		if snap.safety.MaxDetectorTimeout > 0 && detectorNeedsTimeout(detector) {
			dctx, cancel = context.WithTimeout(ctx, snap.safety.MaxDetectorTimeout)
		}
		got, err := detector.Detect(dctx, sec, event)
		cancel()
		g.recordDetector(ctx, detector.ID(), len(got), err, time.Since(detectorStarted))
		if err != nil {
			findings = append(findings, Finding{ID: detector.ID() + "_error", Risk: 10, Confidence: 1, Message: err.Error()})
			continue
		}
		findings = append(findings, got...)
	}
	applyThreatModels(findings, snap.threatModels)
	var results []RuleResult
	eventTypes := g.deriveEventTypes(ctx, sec, event, snap.derived)
	candidates := snap.ruleIndex.candidatesForIndexed(eventTypes, sec, snap.rules, snap.indexEnabled)
	for _, ruleIndex := range candidates {
		if ruleIndex < 0 || ruleIndex >= len(snap.rules) {
			continue
		}
		rule := &snap.rules[ruleIndex]
		matched, err := g.matchRule(ctx, sec, eventTypes, rule)
		if err != nil || !matched {
			continue
		}
		risk, _ := scoreRule(ctx, sec, rule, findings)
		severity := resolveSeverity(ctx, sec, rule, risk)
		actions := actionsForSeverity(rule, severity)
		if g.cooldownActive(ctx, sec, rule) {
			actions = filterCooldownActions(actions, snap.actions)
		}
		results = append(results, RuleResult{Rule: rule, Risk: risk, Severity: severity, Findings: findings, Actions: actions})
	}
	results, authzFindings := g.filterByAuthz(ctx, sec, event, results, snap)
	if len(authzFindings) > 0 {
		findings = append(findings, authzFindings...)
	}
	decision = decide(snap.mode, snap.defaultEffect, sec, event, findings, results)
	applyLookupFailures(sec, &decision)
	decision.Evidence = buildEvidence(sec, results, findings)
	decision.PolicyVersion = snap.policyVersion
	decision.ConfigHash = snap.configHash
	if snap.profilesEnabled {
		decision.Profiles = g.updateEntityProfiles(ctx, sec, decision, results)
	}
	actionRefs := decisionActionRefs(results)
	actionRefs, decision.Approvals = g.resolveApprovalGate(ctx, sec, results, actionRefs)
	if len(decision.Approvals) > 0 {
		decision.Effect = DecisionChallenge
		decision.Allowed = false
		decision.Explanation = buildApprovalChallengeExplanation(sec, decision.Approvals)
	}
	for _, ref := range actionRefs {
		result := g.executeActionWithSnapshot(ctx, sec, decision, ref, snap)
		decision.Actions = append(decision.Actions, result)
		if result.Type == "create_incident" && result.Status == "ok" {
			incident := Incident{ID: result.ID, Severity: decision.Severity, Status: "open", Summary: decision.Explanation, CreatedAt: result.At}
			decision.Incidents = append(decision.Incidents, incident)
		}
	}
	g.markCooldowns(ctx, sec, results)
	decision.Audit = AuditRecord{
		RequestID:          sec.Request.ID,
		Event:              event.Type,
		Decision:           string(decision.Effect),
		RiskScore:          decision.Risk.Score,
		Severity:           decision.Severity,
		MatchedRules:       decision.MatchedRules,
		Findings:           findingIDs(decision.Findings),
		Evidence:           evidenceIDs(decision.Evidence),
		ActionResults:      decision.Actions,
		ApprovalIDs:        approvalIDs(decision.Approvals),
		Explanation:        decision.Explanation,
		RequestFingerprint: requestFingerprint(sec),
		PolicyVersion:      snap.policyVersion,
		ConfigHash:         snap.configHash,
		At:                 time.Now().UTC(),
	}
	g.persistAudit(ctx, sec, &decision)
	return decision
}

func (g *Guard) persistAudit(ctx context.Context, sec *Context, decision *Decision) {
	if !g.auditEnabled || g.auditStore == nil || decision == nil {
		return
	}
	if decision.Audit.RequestFingerprint == "" {
		decision.Audit.RequestFingerprint = requestFingerprint(sec)
	}
	envelope, err := g.auditStore.SaveAuditEnvelope(ctx, decision.Audit)
	if err == nil {
		decision.AuditEnvelope = &envelope
	}
}

func (g *Guard) recordDecision(ctx context.Context, sec *Context, decision Decision, duration time.Duration) {
	g.mu.RLock()
	recorder := g.metrics
	g.mu.RUnlock()
	if recorder != nil {
		recorder.RecordDecision(ctx, sec, decision, duration)
	}
}

func (g *Guard) recordDetector(ctx context.Context, id string, findings int, err error, duration time.Duration) {
	g.mu.RLock()
	recorder := g.metrics
	g.mu.RUnlock()
	if recorder != nil {
		recorder.RecordDetector(ctx, id, findings, err, duration)
	}
}

func (g *Guard) recordAction(ctx context.Context, sec *Context, decision Decision, result ActionResult, duration time.Duration) {
	g.mu.RLock()
	recorder := g.metrics
	g.mu.RUnlock()
	if recorder != nil {
		recorder.RecordAction(ctx, sec, decision, result, duration)
	}
}

func (g *Guard) recordReload(ctx context.Context, ok bool, duration time.Duration) {
	g.mu.RLock()
	recorder := g.metrics
	g.mu.RUnlock()
	if recorder != nil {
		recorder.RecordReload(ctx, ok, duration)
	}
}

func (g *Guard) blockedByState(ctx context.Context, sec *Context) (bool, Finding) {
	return g.cacheStateGates(ctx, sec)
}

func (g *Guard) filterByAuthz(ctx context.Context, sec *Context, event Event, results []RuleResult, snap *runtimeSnapshot) ([]RuleResult, []Finding) {
	if len(results) == 0 || snap == nil || snap.authzProvider == nil {
		return results, nil
	}
	out := make([]RuleResult, 0, len(results))
	var denied []Finding
	for _, result := range results {
		if result.Rule == nil {
			out = append(out, result)
			continue
		}
		policy := strings.TrimSpace(result.Rule.AuthzPolicy)
		if policy == "" {
			if snap.authzStrict {
				denied = append(denied, finding("authz_policy_required", 100, "missing authz policy binding for matched rule "+result.Rule.ID))
				continue
			}
			out = append(out, result)
			continue
		}
		req := AuthzRequest{
			Policy:    policy,
			RuleID:    result.Rule.ID,
			Action:    strings.ToUpper(firstNonEmpty(sec.Request.Method, event.Type, "evaluate")),
			Resource:  "route:" + strings.ToUpper(firstNonEmpty(sec.Request.Method, "GET")) + ":" + firstNonEmpty(sec.Request.Path, sec.Business.Entity, "/"),
			EventType: event.Type,
			Context:   sec,
			Subject: map[string]any{
				"id":          firstNonEmpty(sec.Identity.ID, "anonymous"),
				"type":        "user",
				"tenant_id":   firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant),
				"roles":       authzRoles(sec.Identity),
				"permissions": sec.Identity.Permissions,
			},
			Attrs: map[string]any{
				"request.path":     sec.Request.Path,
				"request.method":   sec.Request.Method,
				"network.ip":       sec.Network.IP,
				"tenant.id":        firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant),
				"business.action":  sec.Business.Action,
				"business.entity":  sec.Business.Entity,
				"runtime.policy":   snap.policyVersion,
				"runtime.rule_id":  result.Rule.ID,
				"runtime.event":    event.Type,
				"identity.subject": sec.Identity.ID,
			},
		}
		if sec.Request.Params != nil {
			if owner := strings.TrimSpace(sec.Request.Params["id"]); owner != "" {
				req.Attrs["resource.owner_id"] = owner
			}
		}
		authzCtx := ctx
		cancel := func() {}
		if snap.authzConfig.Timeout > 0 {
			authzCtx, cancel = context.WithTimeout(ctx, snap.authzConfig.Timeout)
		}
		decision, err := snap.authzProvider.Authorize(authzCtx, req)
		cancel()
		if err != nil {
			if snap.authzConfig.ErrorPolicy == AuthzErrorAllow && !snap.authzStrict {
				out = append(out, result)
				continue
			}
			denied = append(denied, finding("authz_error_"+result.Rule.ID, 100, "authorization failed: "+err.Error()))
			continue
		}
		result.Authz = &decision.Evidence
		if !decision.Allowed {
			reason := decision.Evidence.Reason
			if strings.TrimSpace(reason) == "" {
				reason = "authorization denied"
			}
			denied = append(denied, finding("authz_denied_"+result.Rule.ID, 100, reason))
			continue
		}
		out = append(out, result)
	}
	return out, denied
}

func authzRoles(identity IdentityContext) []string {
	roles := append([]string(nil), identity.Roles...)
	if identity.Role != "" && !slices.Contains(roles, identity.Role) {
		roles = append(roles, identity.Role)
	}
	return roles
}

func (g *Guard) cacheStateGates(ctx context.Context, sec *Context) (bool, Finding) {
	if g.store == nil {
		return false, Finding{}
	}
	var first Finding
	if sec.Network.IP != "" {
		first = g.checkStateGateJoined(ctx, first, "ban:ip:", sec.Network.IP, "banned_ip", "IP is temporarily banned", "state.ip_banned", sec)
	}
	if sec.Network.Country != "" {
		first = g.checkStateGateJoined(ctx, first, "ban:country:", sec.Network.Country, "blocked_country", "country is blocked", "state.country_blocked", sec)
	}
	if sec.Network.ASN != "" {
		first = g.checkStateGateJoined(ctx, first, "ban:asn:", sec.Network.ASN, "banned_asn", "ASN is temporarily banned", "state.asn_banned", sec)
	}
	if sec.Identity.ID != "" {
		first = g.checkStateGateJoined(ctx, first, "lock:user:", sec.Identity.ID, "locked_user", "user is locked", "state.user_locked", sec)
		first = g.checkStateGateJoined(ctx, first, "revoke:sessions:", sec.Identity.ID, "revoked_user_sessions", "user sessions are revoked", "state.user_sessions_revoked", sec)
	}
	if sec.Session.ID != "" {
		first = g.checkStateGateJoined(ctx, first, "revoke:session:", sec.Session.ID, "revoked_session", "session is revoked", "state.session_revoked", sec)
	}
	if sec.Request.Headers != nil {
		if key := sec.Request.Headers["X-API-Key"]; key != "" {
			first = g.checkStateGateJoined(ctx, first, "disable:apikey:", key, "disabled_api_key", "API key is disabled", "state.api_key_disabled", sec)
		}
	}
	if first.ID != "" {
		return true, first
	}
	return false, Finding{}
}

func (g *Guard) checkStateGate(ctx context.Context, first Finding, key, findingID, message, fact string, sec *Context) Finding {
	if _, found, err := g.store.Get(ctx, key); err == nil && found {
		setContextFact(sec, fact, true)
		if first.ID == "" {
			first = finding(findingID, 100, message)
		}
	}
	return first
}

func (g *Guard) checkStateGateJoined(ctx context.Context, first Finding, prefix, value, findingID, message, fact string, sec *Context) Finding {
	var found bool
	var err error
	if store, ok := g.store.(*MemoryStore); ok {
		found, err = store.HasJoined(ctx, prefix, value)
	} else {
		_, found, err = g.store.Get(ctx, prefix+value)
	}
	if err == nil && found {
		setContextFact(sec, fact, true)
		if first.ID == "" {
			first = finding(findingID, 100, message)
		}
	}
	return first
}

func (g *Guard) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		result, err := g.EvaluateHTTPRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		for _, action := range result.Decision.Actions {
			if action.Type == "add_risk_header" || action.ID == "add_risk_header" {
				w.Header().Set("X-TCPGuard-Risk", fmt.Sprintf("%.0f", result.Decision.Risk.Score))
			}
		}
		if result.Enforced {
			writeHTTPResponse(w, result.Response)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HTTPRequestResult is the framework-neutral result of evaluating an HTTP
// request. Adapters can use Response when Enforced is true, or continue their
// framework's handler chain otherwise.
type HTTPRequestResult struct {
	Context  *Context
	Decision Decision
	Response DecisionResponse
	Enforced bool
}

// EvaluateHTTPRequest evaluates an HTTP request without writing a response or
// invoking another handler. It is the integration point for framework adapters.
// Callers that pass the request downstream are responsible for preserving or
// restoring its body if their ContextBuilder or detectors consume it.
func (g *Guard) EvaluateHTTPRequest(r *http.Request) (HTTPRequestResult, error) {
	if r == nil {
		return HTTPRequestResult{}, errors.New("tcpguard: nil HTTP request")
	}
	sec, err := g.builder.BuildHTTP(r.Context(), r)
	if err != nil {
		return HTTPRequestResult{}, err
	}
	snap := g.snapshot.Load()
	if snap == nil {
		g.mu.RLock()
		snap = newRuntimeSnapshot(g)
		g.mu.RUnlock()
	}
	if snap.authzProvider != nil && snap.authzConfig.EnforceHTTP {
		authzDecision, authzErr := authorizeHTTPContext(r.Context(), snap.authzProvider, snap.authzConfig, sec)
		if authzErr != nil && snap.authzConfig.ErrorPolicy == AuthzErrorAllow && !snap.authzStrict {
			authzErr = nil
			authzDecision.Allowed = true
		}
		if authzErr != nil || !authzDecision.Allowed {
			reason := authzDecision.Evidence.Reason
			if authzErr != nil {
				reason = "authorization failed: " + authzErr.Error()
			}
			if strings.TrimSpace(reason) == "" {
				reason = "authorization denied"
			}
			findingID := "authz_http_denied"
			if authzErr != nil {
				findingID = "authz_http_error"
			}
			finding := finding(findingID, 100, reason)
			decision := Decision{
				Effect: DecisionBlock, Allowed: false, Risk: Risk{Score: 100, Confidence: 1},
				Severity: SeverityCritical, Findings: []Finding{finding}, Explanation: reason,
				PolicyVersion: snap.policyVersion, ConfigHash: snap.configHash,
				Evidence: []Evidence{{Type: "authz", ID: authzDecision.Evidence.MatchedBy, Message: reason, Fields: map[string]any{
					"provider": authzDecision.Evidence.Provider, "allowed": false, "matched_by": authzDecision.Evidence.MatchedBy,
				}}},
			}
			decision.Audit = AuditRecord{
				RequestID: sec.Request.ID, Event: "request.received", Decision: string(decision.Effect),
				RiskScore: 100, Severity: SeverityCritical, Findings: []string{findingID},
				Evidence: []string{"authz:" + authzDecision.Evidence.MatchedBy}, Explanation: reason,
				RequestFingerprint: requestFingerprint(sec), PolicyVersion: snap.policyVersion, ConfigHash: snap.configHash, At: time.Now().UTC(),
			}
			g.persistAudit(r.Context(), sec, &decision)
			result := HTTPRequestResult{Context: sec, Decision: decision, Enforced: g.enforced(decision)}
			if result.Enforced {
				result.Response = g.renderDecisionResponse(sec, decision)
			}
			return result, nil
		}
	}
	decision := g.Evaluate(r.Context(), Event{Type: "request.received", RequestID: sec.Request.ID}, sec)
	result := HTTPRequestResult{Context: sec, Decision: decision, Enforced: g.enforced(decision)}
	if result.Enforced {
		result.Response = g.renderDecisionResponse(sec, decision)
	}
	return result, nil
}

func (g *Guard) RegisterDetector(detector Detector) {
	if detector == nil {
		return
	}
	g.mu.Lock()
	g.detectors = append(g.detectors, detector)
	g.publishSnapshotLocked()
	g.mu.Unlock()
}

func (g *Guard) RegisterEnricher(enricher Enricher) {
	if enricher == nil {
		return
	}
	g.mu.Lock()
	g.enrichers = append(g.enrichers, enricher)
	g.publishSnapshotLocked()
	g.mu.Unlock()
}

func (g *Guard) RegisterAction(actionType string, executor ActionExecutor) {
	if actionType == "" || executor == nil {
		return
	}
	g.mu.Lock()
	if g.actionHandlers == nil {
		g.actionHandlers = map[string]ActionExecutor{}
	}
	g.actionHandlers[actionType] = executor
	g.publishSnapshotLocked()
	g.mu.Unlock()
}

func (g *Guard) RegisterDataSource(source DataSource) {
	if source == nil || source.ID() == "" {
		return
	}
	g.mu.Lock()
	if g.datasources == nil {
		g.datasources = map[string]DataSource{}
	}
	g.datasources[source.ID()] = source
	g.publishSnapshotLocked()
	g.mu.Unlock()
}

func (g *Guard) ListApprovals(ctx context.Context, status ApprovalStatus) ([]ApprovalRecord, error) {
	if g.approvalStore == nil {
		return nil, nil
	}
	return g.approvalStore.ListApprovals(ctx, status)
}

func (g *Guard) GetApproval(ctx context.Context, id string) (ApprovalRecord, bool, error) {
	if g.approvalStore == nil {
		return ApprovalRecord{}, false, nil
	}
	return g.approvalStore.GetApproval(ctx, id)
}

func (g *Guard) Approve(ctx context.Context, id, approver, reason string) (ApprovalRecord, error) {
	return g.decideApproval(ctx, id, ApprovalApproved, approver, reason)
}

func (g *Guard) Reject(ctx context.Context, id, approver, reason string) (ApprovalRecord, error) {
	return g.decideApproval(ctx, id, ApprovalRejected, approver, reason)
}

func (g *Guard) decideApproval(ctx context.Context, id string, status ApprovalStatus, approver, reason string) (ApprovalRecord, error) {
	if g.approvalStore == nil {
		return ApprovalRecord{}, errors.New("tcpguard: approval store is not configured")
	}
	record, found, err := g.approvalStore.GetApproval(ctx, id)
	if err != nil {
		return ApprovalRecord{}, err
	}
	if !found {
		return ApprovalRecord{}, errors.New("tcpguard: approval request not found")
	}
	if len(record.Approvers) > 0 && !stringIn(approver, record.Approvers) {
		return ApprovalRecord{}, fmt.Errorf("tcpguard: %s is not an allowed approver", approver)
	}
	record.Status = status
	record.DecidedAt = time.Now().UTC()
	record.DecidedBy = approver
	record.Reason = reason
	return record, g.approvalStore.UpdateApproval(ctx, record)
}

func (g *Guard) enforced(decision Decision) bool {
	g.mu.RLock()
	mode := g.mode
	g.mu.RUnlock()
	if mode != Enforce {
		return false
	}
	return decision.Effect == DecisionBlock || decision.Effect == DecisionThrottle || decision.Effect == DecisionChallenge || decision.Effect == DecisionRevoke
}

func (g *Guard) matchRule(ctx context.Context, sec *Context, eventTypes []string, rule *Rule) (bool, error) {
	if rule.Status != RuleActive && rule.Status != RuleShadow && rule.Status != RuleTesting {
		return false, nil
	}
	if len(rule.Triggers) > 0 && !anyStringIn(eventTypes, rule.Triggers) {
		return false, nil
	}
	if rule.Sequence != nil {
		ok, err := g.matchSequence(ctx, sec, eventTypes, rule)
		if err != nil || !ok {
			return false, err
		}
	}
	if len(eventTypes) == 0 {
		return false, nil
	}
	if !scopeMatches(rule, sec) {
		return false, nil
	}
	if rule.compiled == nil {
		return true, nil
	}
	res, err := rule.compiled.Eval(ctx, sec.Facts)
	return res.Matched, err
}

type sequenceState struct {
	Index int `json:"index"`
	Count int `json:"count"`
}

func (g *Guard) matchSequence(ctx context.Context, sec *Context, eventTypes []string, rule *Rule) (bool, error) {
	if g.store == nil || rule.Sequence == nil || len(rule.Sequence.Steps) == 0 {
		return false, nil
	}
	key := "sequence:" + rule.ID + ":" + sequenceEntity(sec)
	var state sequenceState
	if data, found, err := g.store.Get(ctx, key); err != nil {
		return false, err
	} else if found {
		_ = json.Unmarshal(data, &state)
	}
	if state.Index < 0 || state.Index >= len(rule.Sequence.Steps) {
		state = sequenceState{}
	}
	step := rule.Sequence.Steps[state.Index]
	if !stringIn(step.Event, eventTypes) {
		first := rule.Sequence.Steps[0]
		if stringIn(first.Event, eventTypes) {
			state = sequenceState{}
			step = first
		} else {
			return false, nil
		}
	}
	required := step.Count
	if required <= 0 {
		required = 1
	}
	state.Count++
	if state.Count < required {
		return false, g.saveSequence(ctx, key, state, rule.Sequence.Within)
	}
	state.Index++
	state.Count = 0
	if state.Index >= len(rule.Sequence.Steps) {
		_ = g.store.Delete(ctx, key)
		return true, nil
	}
	return false, g.saveSequence(ctx, key, state, rule.Sequence.Within)
}

func (g *Guard) saveSequence(ctx context.Context, key string, state sequenceState, ttl time.Duration) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return g.store.Set(ctx, key, data, ttl)
}

func sequenceEntity(sec *Context) string {
	switch {
	case sec.Identity.ID != "":
		return "user:" + sec.Identity.ID
	case sec.Session.ID != "":
		return "session:" + sec.Session.ID
	case sec.Network.IP != "":
		return "ip:" + sec.Network.IP
	default:
		return "request:" + sec.Request.ID
	}
}

func (g *Guard) deriveEventTypes(ctx context.Context, sec *Context, event Event, triggers []DerivedTrigger) []string {
	types := []string{event.Type}
	for _, trigger := range triggers {
		if trigger.Source != "" && trigger.Source != event.Type {
			continue
		}
		if trigger.compiled != nil {
			res, err := trigger.compiled.Eval(ctx, sec.Facts)
			if err != nil || !res.Matched {
				continue
			}
		} else if trigger.Condition != "" {
			continue
		}
		emit := trigger.Emit
		if emit == "" {
			emit = trigger.ID
		}
		types = append(types, emit)
	}
	return types
}

func (g *Guard) markCooldowns(ctx context.Context, sec *Context, results []RuleResult) {
	if g.store == nil {
		return
	}
	for _, result := range results {
		if result.Rule.Cooldown.Key == "" || result.Rule.Cooldown.Duration <= 0 {
			continue
		}
		key := cooldownKey(sec, result.Rule)
		if _, found, err := g.store.Get(ctx, key); err != nil || found {
			continue
		}
		_ = g.store.Set(ctx, key, []byte("1"), result.Rule.Cooldown.Duration)
	}
}

func (g *Guard) cooldownActive(ctx context.Context, sec *Context, rule *Rule) bool {
	if g.store == nil || rule == nil || rule.Cooldown.Key == "" || rule.Cooldown.Duration <= 0 {
		return false
	}
	_, found, err := g.store.Get(ctx, cooldownKey(sec, rule))
	return err == nil && found
}

func cooldownKey(sec *Context, rule *Rule) string {
	return "cooldown:" + rule.ID + ":" + valueForPath(sec, rule.Cooldown.Key)
}

func (g *Guard) updateEntityProfiles(ctx context.Context, sec *Context, decision Decision, results []RuleResult) []EntityProfile {
	if g.store == nil || decision.Risk.Score <= 0 {
		return nil
	}
	entities := map[string]string{
		"user":            sec.Identity.ID,
		"session":         sec.Session.ID,
		"device":          firstNonEmpty(sec.Device.ID, sec.Session.DeviceID),
		"ip":              sec.Network.IP,
		"tenant":          firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant),
		"endpoint":        sec.Request.Path,
		"api_key":         sec.Request.Headers["X-API-Key"],
		"business_action": sec.Business.Action,
	}
	decay := 24 * time.Hour
	for _, result := range results {
		if result.Rule.Risk.Decay > 0 {
			decay = result.Rule.Risk.Decay
			break
		}
	}
	now := time.Now().UTC()
	var out []EntityProfile
	for entity, id := range entities {
		if id == "" {
			continue
		}
		key := "profile:" + entity + ":" + id
		profile := EntityProfile{Entity: entity, ID: id}
		if data, found, err := g.store.Get(ctx, key); err == nil && found {
			_ = json.Unmarshal(data, &profile)
		}
		previous := profile.RiskScore
		if !profile.LastSeenAt.IsZero() && decay > 0 {
			age := now.Sub(profile.LastSeenAt)
			if age > 0 {
				remaining := 1 - age.Seconds()/decay.Seconds()
				if remaining < 0 {
					remaining = 0
				}
				previous *= remaining
			}
		}
		if decision.Risk.Score > previous {
			profile.RiskScore = decision.Risk.Score
		} else {
			profile.RiskScore = previous
		}
		profile.Confidence = decision.Risk.Confidence
		profile.LastSeenAt = now
		data, _ := json.Marshal(profile)
		_ = g.store.Set(ctx, key, data, 0)
		out = append(out, profile)
		setFact(sec.Facts, "risk.profile."+entity+".score", profile.RiskScore)
	}
	return out
}

func (g *Guard) executeAction(ctx context.Context, sec *Context, decision Decision, ref ActionRef) ActionResult {
	started := time.Now()
	def := g.actions[ref.ID]
	actionType := def.Type
	if actionType == "" {
		actionType = ref.ID
	}
	if g.safety.MaxActionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.safety.MaxActionTimeout)
		defer cancel()
	}
	handler := g.actionHandlers[actionType]
	if handler == nil {
		result := ActionResult{ID: ref.ID, Type: actionType, Status: "skipped", Error: "no action handler registered", At: time.Now().UTC()}
		g.recordAction(ctx, sec, decision, result, time.Since(started))
		return result
	}
	result := handler.Execute(ctx, sec, decision, ref)
	g.recordAction(ctx, sec, decision, result, time.Since(started))
	return result
}

func (g *Guard) executeActionWithSnapshot(ctx context.Context, sec *Context, decision Decision, ref ActionRef, snap *runtimeSnapshot) ActionResult {
	started := time.Now()
	if snap == nil {
		return g.executeAction(ctx, sec, decision, ref)
	}
	def := snap.actions[ref.ID]
	actionType := def.Type
	if actionType == "" {
		actionType = ref.ID
	}
	if snap.safety.MaxActionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, snap.safety.MaxActionTimeout)
		defer cancel()
	}
	handler := snap.actionHandlers[actionType]
	if handler == nil {
		result := ActionResult{ID: ref.ID, Type: actionType, Status: "skipped", Error: "no action handler registered", At: time.Now().UTC()}
		g.recordAction(ctx, sec, decision, result, time.Since(started))
		return result
	}
	result := handler.Execute(ctx, sec, decision, ref)
	g.recordAction(ctx, sec, decision, result, time.Since(started))
	return result
}

func DefaultPolicySafety() PolicySafety {
	return PolicySafety{
		MaxRuleEvalTime:    2 * time.Millisecond,
		MaxDetectorTimeout: 50 * time.Millisecond,
		MaxLookupTimeout:   25 * time.Millisecond,
		MaxActionTimeout:   5 * time.Second,
		MaxActionsPerRule:  10,
		MaxLookupsPerEval:  20,
		MaxRetryCount:      3,
		MaxWebhookTimeout:  5 * time.Second,
		CommandEnabled:     false,
	}
}

func validateRulesAgainstSafety(rules []Rule, actions map[string]ActionDefinition, safety PolicySafety) error {
	allowlist := map[string]bool{}
	for _, action := range safety.ActionAllowlist {
		allowlist[action] = true
	}
	approvalRequired := map[string]bool{}
	for _, action := range safety.RequireApprovalFor {
		approvalRequired[action] = true
	}
	for _, rule := range rules {
		for severity, refs := range rule.Actions {
			if safety.MaxActionsPerRule > 0 && len(refs) > safety.MaxActionsPerRule {
				return fmt.Errorf("tcpguard: rule %s severity %s has %d actions above limit %d", rule.ID, severity, len(refs), safety.MaxActionsPerRule)
			}
			for _, ref := range refs {
				def := actions[ref.ID]
				actionType := firstNonEmpty(def.Type, ref.ID)
				if len(allowlist) > 0 && !allowlist[actionType] && !allowlist[ref.ID] {
					return fmt.Errorf("tcpguard: rule %s action %s type %s is not allowlisted", rule.ID, ref.ID, actionType)
				}
				if actionType == "command" && !safety.CommandEnabled {
					return fmt.Errorf("tcpguard: command action %s is disabled by policy_safety", ref.ID)
				}
				if approvalRequired[actionType] && !rule.Approval.Required {
					return fmt.Errorf("tcpguard: rule %s action %s requires approval", rule.ID, actionType)
				}
				if safety.MaxRetryCount > 0 && def.Retry.Attempts > safety.MaxRetryCount {
					return fmt.Errorf("tcpguard: action %s retry attempts %d above limit %d", ref.ID, def.Retry.Attempts, safety.MaxRetryCount)
				}
				if safety.MaxWebhookTimeout > 0 && actionType == "webhook" && def.Timeout > safety.MaxWebhookTimeout {
					return fmt.Errorf("tcpguard: webhook action %s timeout %s above limit %s", ref.ID, def.Timeout, safety.MaxWebhookTimeout)
				}
			}
		}
	}
	return nil
}

func validateActionDefinitions(actions map[string]ActionDefinition, safety PolicySafety) error {
	for id, def := range actions {
		if err := validateStatusRangeDefs(def.SuccessCodes); err != nil {
			return fmt.Errorf("tcpguard: action %s has invalid success_codes: %w", id, err)
		}
		if err := validateStatusRangeDefs(def.RetryOnCodes); err != nil {
			return fmt.Errorf("tcpguard: action %s has invalid retry_on_codes: %w", id, err)
		}
		actionType := firstNonEmpty(def.Type, id)
		if actionType == "webhook" || actionType == "notify_admin" || actionType == "notify_user" || actionType == "notify_soc" || actionType == "siem" || actionType == "event_bus" {
			endpoint := firstNonEmpty(def.Request.Endpoint, def.Endpoint)
			if endpoint != "" {
				if err := validateOutboundURL(endpoint, def.AllowPrivateURL); err != nil {
					return fmt.Errorf("tcpguard: action %s endpoint is not allowed: %w", id, err)
				}
			}
		}
		if safety.MaxRetryCount > 0 && def.Retry.Attempts > safety.MaxRetryCount {
			return fmt.Errorf("tcpguard: action %s retry attempts %d above limit %d", id, def.Retry.Attempts, safety.MaxRetryCount)
		}
		if err := validateActionRefs(def); err != nil {
			return fmt.Errorf("tcpguard: action %s has invalid ref: %w", id, err)
		}
	}
	return nil
}

func validateActionRefs(def ActionDefinition) error {
	var validateAny func(v any) error
	validateAny = func(v any) error {
		switch x := v.(type) {
		case EnvRef:
			if !validRefArgs(decodeRefArgs(string(x))) {
				return errors.New("env ref requires 1 or 2 args")
			}
		case ContextRef:
			if !validRefArgs(decodeRefArgs(string(x))) {
				return errors.New("context ref requires 1 or 2 args")
			}
		case SessionRef:
			if !validRefArgs(decodeRefArgs(string(x))) {
				return errors.New("session ref requires 1 or 2 args")
			}
		case map[string]any:
			for _, child := range x {
				if err := validateAny(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range x {
				if err := validateAny(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := validateAny(def.Request.Body); err != nil {
		return err
	}
	if err := validateAny(def.Request.Fields); err != nil {
		return err
	}
	return nil
}

func applyThreatModels(findings []Finding, models []ThreatModelDefinition) {
	if len(findings) == 0 || len(models) == 0 {
		return
	}
	for i := range findings {
		for _, model := range models {
			for category, ids := range model.Categories {
				if stringIn(findings[i].ID, ids) || stringIn(findings[i].Type, ids) {
					if findings[i].ThreatCategories == nil {
						findings[i].ThreatCategories = map[string][]string{}
					}
					findings[i].ThreatCategories[model.ID] = appendUnique(findings[i].ThreatCategories[model.ID], category)
					modelID := strings.ToLower(model.ID)
					if strings.HasPrefix(modelID, "mitre") {
						findings[i].MITRE = appendUnique(findings[i].MITRE, category)
					} else if strings.HasPrefix(modelID, "stride") {
						findings[i].STRIDE = appendUnique(findings[i].STRIDE, category)
					}
				}
			}
		}
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func compileRule(rule *Rule) error {
	if rule.ID == "" {
		return errors.New("tcpguard: rule id is required")
	}
	rule.scopePaths = rule.scopePaths[:0]
	rule.riskAdders = rule.riskAdders[:0]
	rule.severityExpr = rule.severityExpr[:0]
	rule.needsRiskFacts = false
	if rule.Condition != "" {
		expr, err := condition.Compile(normalizeCondition(rule.Condition))
		if err != nil {
			return fmt.Errorf("tcpguard: compile rule %s: %w", rule.ID, err)
		}
		rule.compiled = expr
	}
	for _, path := range rule.Scope.Paths {
		rule.scopePaths = append(rule.scopePaths, compilePathPattern(path))
	}
	for i := range rule.Risk.Adders {
		adder := compiledRiskAdder{spec: rule.Risk.Adders[i]}
		if adder.spec.Condition != "" {
			expr, err := condition.Compile(normalizeCondition(adder.spec.Condition))
			if err != nil {
				return err
			}
			adder.expr = expr
			rule.needsRiskFacts = true
		}
		if adder.spec.Field != "" {
			rule.needsRiskFacts = true
		}
		rule.riskAdders = append(rule.riskAdders, adder)
	}
	for i := range rule.Severity {
		sr := compiledSeverityRule{spec: rule.Severity[i]}
		if sr.spec.Condition != "" {
			if op, value, ok := parseRiskScoreSeverityCondition(sr.spec.Condition); ok {
				sr.riskScoreOp = op
				sr.riskScoreValue = value
			} else {
				expr, err := condition.Compile(normalizeCondition(sr.spec.Condition))
				if err != nil {
					return err
				}
				sr.expr = expr
				rule.needsRiskFacts = true
			}
		}
		rule.severityExpr = append(rule.severityExpr, sr)
	}
	return nil
}

func scoreRule(ctx context.Context, sec *Context, rule *Rule, findings []Finding) (Risk, error) {
	score := rule.Risk.Base
	confidence := 0.0
	for _, finding := range findings {
		if finding.Risk > score {
			score = finding.Risk
		}
		if finding.Confidence > confidence {
			confidence = finding.Confidence
		}
	}
	for _, adder := range rule.riskAdders {
		if adder.expr != nil {
			res, err := adder.expr.Eval(ctx, sec.Facts)
			if err != nil {
				return Risk{}, err
			}
			if !res.Matched {
				continue
			}
		}
		if adder.spec.Field != "" {
			if v, ok := sec.Facts.Get(adder.spec.Field); ok {
				if f, ok := number(v); ok {
					score += f * adder.spec.Scale
					continue
				}
			}
		}
		score += adder.spec.Value
	}
	if rule.Risk.Max > 0 && score > rule.Risk.Max {
		score = rule.Risk.Max
	}
	if score > 100 {
		score = 100
	}
	if confidence == 0 && score > 0 {
		confidence = 0.75
	}
	if rule.needsRiskFacts {
		setFact(sec.Facts, "risk.score", score)
		setFact(sec.Facts, "risk.confidence", confidence)
	}
	return Risk{Score: score, Confidence: confidence}, nil
}

func resolveSeverity(ctx context.Context, sec *Context, rule *Rule, risk Risk) Severity {
	if rule.needsRiskFacts {
		setFact(sec.Facts, "risk.score", risk.Score)
	}
	severity := severityForRisk(risk.Score)
	for _, sr := range rule.severityExpr {
		if sr.riskScoreOp != "" {
			if matchRiskScoreSeverity(risk.Score, sr.riskScoreOp, sr.riskScoreValue) {
				severity = sr.spec.Severity
			}
			continue
		}
		if sr.expr == nil {
			continue
		}
		res, err := sr.expr.Eval(ctx, sec.Facts)
		if err == nil && res.Matched {
			severity = sr.spec.Severity
		}
	}
	return severity
}

func parseRiskScoreSeverityCondition(condition string) (string, float64, bool) {
	fields := strings.Fields(strings.TrimSpace(condition))
	if len(fields) != 3 || fields[0] != "risk.score" {
		return "", 0, false
	}
	switch fields[1] {
	case ">=", ">", "<=", "<", "==":
	default:
		return "", 0, false
	}
	value, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return "", 0, false
	}
	return fields[1], value, true
}

func matchRiskScoreSeverity(score float64, op string, value float64) bool {
	switch op {
	case ">=":
		return score >= value
	case ">":
		return score > value
	case "<=":
		return score <= value
	case "<":
		return score < value
	case "==":
		return score == value
	default:
		return false
	}
}

func decide(mode Mode, defaultEffect DecisionEffect, sec *Context, event Event, findings []Finding, results []RuleResult) Decision {
	isDeny := defaultEffect == DecisionBlock || defaultEffect == DecisionDeny
	allowed := !isDeny
	decision := Decision{Effect: defaultEffect, Allowed: allowed, Findings: findings, Severity: SeverityInfo}
	if mode == Monitor || mode == Shadow || mode == DryRun {
		decision.Effect = DecisionMonitor
		decision.Allowed = true
	}
	for _, result := range results {
		decision.MatchedRules = append(decision.MatchedRules, result.Rule.ID)
		if result.Risk.Score > decision.Risk.Score {
			decision.Risk = result.Risk
			decision.Severity = result.Severity
		}
	}
	if len(results) == 0 {
		decision.Explanation = buildNoMatchExplanation(sec, defaultEffect)
		return decision
	}
	if mode == Enforce {
		switch decision.Severity {
		case SeverityCritical:
			decision.Effect = DecisionBlock
			decision.Allowed = false
		case SeverityHigh:
			decision.Effect = DecisionChallenge
			decision.Allowed = false
		case SeverityMedium:
			decision.Effect = DecisionThrottle
			decision.Allowed = false
		default:
			decision.Effect = DecisionMonitor
			decision.Allowed = true
		}
	}
	decision.Explanation = buildDecisionExplanation(sec, event, decision, results)
	return decision
}

func decisionActionRefs(results []RuleResult) []ActionRef {
	if len(results) == 1 {
		return results[0].Actions
	}
	var out []ActionRef
	for _, result := range results {
		for _, action := range result.Actions {
			if actionRefIn(action, out) {
				continue
			}
			out = append(out, action)
		}
	}
	return out
}

func actionRefIn(target ActionRef, refs []ActionRef) bool {
	for _, ref := range refs {
		if ref.ID != target.ID || len(ref.Args) != len(target.Args) {
			continue
		}
		same := true
		for i := range ref.Args {
			if ref.Args[i] != target.Args[i] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

func (g *Guard) resolveApprovalGate(ctx context.Context, sec *Context, results []RuleResult, refs []ActionRef) ([]ActionRef, []ApprovalRecord) {
	if g.approvalStore == nil || len(refs) == 0 {
		return refs, nil
	}
	hasRequired := false
	for _, result := range results {
		if result.Rule != nil && result.Rule.Approval.Required {
			hasRequired = true
			break
		}
	}
	if !hasRequired {
		return refs, nil
	}
	var approvedActions map[string]bool
	var gated []ApprovalRecord
	for _, result := range results {
		if result.Rule == nil || !result.Rule.Approval.Required {
			continue
		}
		ruleID := result.Rule.ID
		actionIDs := actionRefIDs(result.Actions)
		id := approvalID(sec.Request.ID, ruleID, actionIDs)
		record, found, err := g.approvalStore.GetApproval(ctx, id)
		if err != nil {
			continue
		}
		if found {
			switch record.Status {
			case ApprovalApproved:
				if approvedActions == nil {
					approvedActions = map[string]bool{}
				}
				for _, actionID := range actionIDs {
					approvedActions[actionID] = true
				}
				continue
			case ApprovalRejected:
				gated = append(gated, record)
				continue
			default:
				gated = append(gated, record)
				continue
			}
		}
		record = ApprovalRecord{
			ID:          id,
			Status:      ApprovalPending,
			RuleID:      ruleID,
			RequestID:   sec.Request.ID,
			ActionIDs:   actionIDs,
			Approvers:   append([]string(nil), result.Rule.Approval.Approvers...),
			RequestedAt: time.Now().UTC(),
		}
		if err := g.approvalStore.SaveApproval(ctx, record); err == nil {
			gated = append(gated, record)
		}
	}
	if len(gated) == 0 && len(approvedActions) == 0 {
		return nil, nil
	}
	if len(gated) > 0 {
		return filterApprovedOrNonApprovalActions(refs, approvedActions, results), gated
	}
	return refs, nil
}

func filterApprovedOrNonApprovalActions(refs []ActionRef, approved map[string]bool, results []RuleResult) []ActionRef {
	out := refs[:0]
	for _, ref := range refs {
		if !actionRequiresApproval(ref.ID, results) || approved[ref.ID] {
			out = append(out, ref)
		}
	}
	return out
}

func actionRequiresApproval(actionID string, results []RuleResult) bool {
	for _, result := range results {
		if result.Rule == nil || !result.Rule.Approval.Required {
			continue
		}
		for _, ref := range result.Actions {
			if ref.ID == actionID {
				return true
			}
		}
	}
	return false
}

func actionRefIDs(refs []ActionRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.ID)
	}
	sort.Strings(out)
	return out
}

func approvalID(requestID, ruleID string, actionIDs []string) string {
	var buf [512]byte
	data := append(buf[:0], requestID...)
	data = append(data, 0)
	data = append(data, ruleID...)
	data = append(data, 0)
	for i, actionID := range actionIDs {
		if i > 0 {
			data = append(data, ',')
		}
		data = append(data, actionID...)
	}
	sum := sha256.Sum256(data)
	var out [33]byte
	copy(out[:], "approval_")
	hex.Encode(out[len("approval_"):], sum[:12])
	return string(out[:])
}

func actionsForSeverity(rule *Rule, severity Severity) []ActionRef {
	if len(rule.Actions) == 0 {
		return nil
	}
	return rule.Actions[severity]
}

func filterCooldownActions(actions []ActionRef, definitions map[string]ActionDefinition) []ActionRef {
	if len(actions) == 0 {
		return nil
	}
	out := make([]ActionRef, 0, len(actions))
	for _, action := range actions {
		if cooldownPreservesAction(action, definitions) {
			out = append(out, action)
		}
	}
	return out
}

func cooldownPreservesAction(action ActionRef, definitions map[string]ActionDefinition) bool {
	actionType := action.ID
	if definitions != nil {
		if def := definitions[action.ID]; def.Type != "" {
			actionType = def.Type
		}
	}
	switch actionType {
	case "allow", "monitor", "add_risk_header",
		"block", "throttle", "delay", "tarpit",
		"captcha_challenge", "mfa_challenge", "reauthenticate",
		"revoke_session", "revoke_all_sessions", "disable_api_key",
		"lock_user", "ban_ip", "ban_asn", "block_country":
		return true
	default:
		return false
	}
}

func scopeMatches(rule *Rule, sec *Context) bool {
	scope := rule.Scope
	if len(scope.Tenants) > 0 && !scopeAllows(scope.Tenants, sec.Tenant.ID, sec.Identity.Tenant) {
		return false
	}
	if len(scope.Roles) > 0 && !scopeAllows(scope.Roles, sec.Identity.Role, sec.Identity.Roles...) {
		return false
	}
	if len(scope.Methods) > 0 && !scopeAllows(scope.Methods, sec.Request.Method) {
		return false
	}
	if len(scope.Paths) > 0 {
		ok := false
		matchers := rule.scopePaths
		if len(matchers) == 0 {
			for _, pattern := range scope.Paths {
				matchers = append(matchers, compilePathPattern(pattern))
			}
		}
		for _, matcher := range matchers {
			matched, params := matcher.Match(sec.Request.Path)
			if matched {
				if len(params) > 0 {
					sec.Request.Params = params
					if sec.Facts != nil {
						setFact(sec.Facts, "request.params", params)
					}
				}
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func scopeAllows(allowed []string, primary string, rest ...string) bool {
	for _, item := range allowed {
		if item == "*" || item == primary || stringIn(item, rest) {
			return true
		}
	}
	return false
}

func stringIn(s string, items []string) bool {
	for _, item := range items {
		if item == s {
			return true
		}
	}
	return false
}

func anyStringIn(values, allowed []string) bool {
	for _, value := range values {
		if stringIn(value, allowed) {
			return true
		}
	}
	return false
}

func valueForPath(sec *Context, path string) string {
	if sec == nil {
		return ""
	}
	if sec.Facts == nil {
		sec.rebuildFacts()
	}
	if value, ok := sec.Facts.Get(path); ok {
		return stringify(value)
	}
	return ""
}

func normalizeCondition(s string) string {
	if converted, ok := normalizeWildcardMatch(s); ok {
		return converted
	}
	replacements := []struct{ old, new string }{
		{" greater_or_equal ", " >= "},
		{" less_or_equal ", " <= "},
		{" greater_than ", " > "},
		{" less_than ", " < "},
		{" not_equals ", " != "},
		{" equals ", " == "},
	}
	out := " " + strings.TrimSpace(s) + " "
	for _, repl := range replacements {
		out = strings.ReplaceAll(out, repl.old, repl.new)
	}
	out = strings.ReplaceAll(out, "store.exists(", "store_exists(")
	out = strings.ReplaceAll(out, "store.value(", "store_value(")
	out = strings.ReplaceAll(out, "store.field(", "store_field(")
	out = strings.ReplaceAll(out, "store.found(", "store_found(")
	out = strings.ReplaceAll(out, "store.error(", "store_error(")
	out = strings.ReplaceAll(out, ".new", ".is_new")
	return strings.TrimSpace(out)
}

func normalizeWildcardMatch(s string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) == 3 && fields[1] == "matches" {
		return fmt.Sprintf("wildcard_match(%s, %s)", fields[0], fields[2]), true
	}
	return "", false
}

func writeHTTPResponse(w http.ResponseWriter, response DecisionResponse) {
	if response.Headers == nil {
		response.Headers = map[string]string{}
	}
	if response.Headers["Content-Type"] == "" {
		response.Headers["Content-Type"] = "application/json"
	}
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(response.Status)
	_ = json.NewEncoder(w).Encode(response.Body)
}

func (g *Guard) renderDecisionResponse(sec *Context, decision Decision) DecisionResponse {
	g.mu.RLock()
	renderer := g.responseRenderer
	g.mu.RUnlock()
	if renderer != nil {
		response := renderer(sec, decision)
		if response.Status == 0 {
			response.Status = httpStatus(decision.Effect)
		}
		if response.Body == nil {
			response.Body = decisionResponse(sec, decision)
		}
		return response
	}
	return DecisionResponse{
		Status:  httpStatus(decision.Effect),
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    decisionResponse(sec, decision),
	}
}

func decisionResponse(sec *Context, decision Decision) map[string]any {
	out := map[string]any{
		"error":         decision.Effect,
		"effect":        decision.Effect,
		"allowed":       decision.Allowed,
		"risk_score":    decision.Risk.Score,
		"confidence":    decision.Risk.Confidence,
		"severity":      decision.Severity,
		"matched_rules": decision.MatchedRules,
		"findings":      findingIDs(decision.Findings),
		"actions":       actionSummaries(decision.Actions),
		"approvals":     approvalResponseSummaries(decision.Approvals),
		"explanation":   decision.Explanation,
	}
	if sec != nil {
		out["request_id"] = sec.Request.ID
		out["rate"] = sec.Rate
		out["path"] = sec.Request.Path
		out["method"] = sec.Request.Method
	}
	return out
}

func httpStatus(effect DecisionEffect) int {
	switch effect {
	case DecisionBlock, DecisionRevoke:
		return http.StatusForbidden
	case DecisionThrottle:
		return http.StatusTooManyRequests
	case DecisionChallenge:
		return http.StatusUnauthorized
	default:
		return http.StatusOK
	}
}

func findingIDs(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.ID)
	}
	return out
}

func actionSummaries(actions []ActionResult) []map[string]any {
	out := make([]map[string]any, 0, len(actions))
	for _, action := range actions {
		item := map[string]any{
			"id":     action.ID,
			"type":   action.Type,
			"status": action.Status,
		}
		if action.Error != "" {
			item["error"] = action.Error
		}
		if len(action.Fields) > 0 {
			item["fields"] = action.Fields
		}
		out = append(out, item)
	}
	return out
}

func approvalResponseSummaries(approvals []ApprovalRecord) []map[string]any {
	out := make([]map[string]any, 0, len(approvals))
	for _, approval := range approvals {
		item := map[string]any{
			"id":         approval.ID,
			"status":     approval.Status,
			"rule_id":    approval.RuleID,
			"action_ids": approval.ActionIDs,
			"approvers":  approval.Approvers,
		}
		if approval.Reason != "" {
			item["reason"] = approval.Reason
		}
		if approval.DecidedBy != "" {
			item["decided_by"] = approval.DecidedBy
		}
		out = append(out, item)
	}
	return out
}

func approvalIDs(approvals []ApprovalRecord) []string {
	out := make([]string, 0, len(approvals))
	for _, approval := range approvals {
		out = append(out, approval.ID)
	}
	return out
}

func requestFingerprint(sec *Context) string {
	if sec == nil {
		return ""
	}
	var buf [512]byte
	data := buf[:0]
	data = appendFingerprintField(data, "id", sec.Request.ID)
	data = appendFingerprintField(data, "method", sec.Request.Method)
	data = appendFingerprintField(data, "path", sec.Request.Path)
	data = appendFingerprintField(data, "ip", sec.Network.IP)
	data = appendFingerprintField(data, "user", sec.Identity.ID)
	data = appendFingerprintField(data, "tenant", firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant))
	data = appendFingerprintField(data, "session", sec.Session.ID)
	data = appendFingerprintField(data, "action", sec.Business.Action)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func appendFingerprintField(dst []byte, key, value string) []byte {
	dst = append(dst, key...)
	dst = append(dst, 0)
	dst = append(dst, value...)
	dst = append(dst, 0)
	return dst
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case uint64:
		return float64(x), true
	default:
		return 0, false
	}
}

func digestRules(rules []Rule, actions map[string]ActionDefinition) string {
	payload := struct {
		Rules   []Rule
		Actions map[string]ActionDefinition
	}{Rules: rules, Actions: actions}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
