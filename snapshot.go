package tcpguard

import (
	"sort"
	"strings"
)

type runtimeSnapshot struct {
	mode            Mode
	policyVersion   string
	configHash      string
	enrichers       []Enricher
	intel           []IntelFeed
	derived         []DerivedTrigger
	detectors       []Detector
	rules           []Rule
	ruleIndex       ruleIndex
	actions         map[string]ActionDefinition
	actionHandlers  map[string]ActionExecutor
	safety          PolicySafety
	threatModels    []ThreatModelDefinition
	datasources     map[string]DataSource
	lookups         []LookupDefinition
	auditEnabled    bool
	profilesEnabled bool
	indexEnabled    bool
	fastNoop        bool
	needsFacts      bool
	needsLookup     bool
	lookupRefs      map[string][]int
	lookupAlways    map[string]bool
	authzProvider   AuthzProvider
	authzConfig     AuthzConfig
	authzStrict     bool
}

type ruleIndex struct {
	allEvents eventRuleIndex
	events    map[string]eventRuleIndex
}

type eventRuleIndex struct {
	noPath   []int
	anyPath  []int
	exact    map[string][]int
	prefixes []pathIndexedRule
	globs    []pathIndexedRule
	routes   []pathIndexedRule
}

type pathIndexedRule struct {
	index   int
	pattern pathPattern
}

func newRuntimeSnapshot(g *Guard) *runtimeSnapshot {
	snap := &runtimeSnapshot{
		mode:            g.mode,
		policyVersion:   g.policyVersion,
		configHash:      g.configHash,
		enrichers:       append([]Enricher(nil), g.enrichers...),
		intel:           append([]IntelFeed(nil), g.intel...),
		derived:         append([]DerivedTrigger(nil), g.derived...),
		detectors:       append([]Detector(nil), g.detectors...),
		rules:           append([]Rule(nil), g.rules...),
		actions:         copyActions(g.actions),
		actionHandlers:  copyActionHandlers(g.actionHandlers),
		safety:          g.safety,
		threatModels:    append([]ThreatModelDefinition(nil), g.threatModels...),
		datasources:     copyDataSources(g.datasources),
		lookups:         append([]LookupDefinition(nil), g.lookups...),
		auditEnabled:    g.auditEnabled,
		profilesEnabled: g.profilesEnabled,
		indexEnabled:    g.fastRuntime,
		authzProvider:   g.authzProvider,
		authzConfig:     g.authzConfig,
		authzStrict:     g.authzStrict,
	}
	snap.ruleIndex = buildRuleIndex(snap.rules)
	snap.needsLookup = len(snap.lookups) > 0 || rulesUseStoreFunctions(snap.rules)
	snap.lookupRefs, snap.lookupAlways = buildLookupUseIndex(snap.lookups, snap.rules, snap.derived)
	snap.needsFacts = rulesNeedFacts(snap.rules) ||
		len(snap.derived) > 0 ||
		snap.needsLookup ||
		len(snap.enrichers) > 0 ||
		len(snap.intel) > 0 ||
		detectorsNeedFacts(snap.detectors)
	snap.fastNoop = len(snap.enrichers) == 0 &&
		len(snap.intel) == 0 &&
		len(snap.derived) == 0 &&
		len(snap.detectors) == 0 &&
		len(snap.rules) == 0 &&
		len(snap.lookups) == 0
	return snap
}

func rulesNeedFacts(rules []Rule) bool {
	for i := range rules {
		rule := &rules[i]
		if rule.compiled != nil || rule.needsRiskFacts {
			return true
		}
		if rule.Cooldown.Key != "" {
			return true
		}
		if rule.Sequence != nil {
			for j := range rule.Sequence.Steps {
				if rule.Sequence.Steps[j].Condition != "" {
					return true
				}
			}
		}
	}
	return false
}

func buildLookupUseIndex(lookups []LookupDefinition, rules []Rule, derived []DerivedTrigger) (map[string][]int, map[string]bool) {
	refs := map[string][]int{}
	always := map[string]bool{}
	for _, lookup := range lookups {
		if lookup.Mode != "preload" {
			continue
		}
		tokens := lookupTokens(lookup)
		for _, trigger := range derived {
			if expressionUsesAny(trigger.Condition, tokens) {
				always[lookup.ID] = true
				break
			}
		}
		if always[lookup.ID] {
			continue
		}
		for i := range rules {
			if ruleUsesAnyLookupToken(rules[i], tokens) {
				refs[lookup.ID] = append(refs[lookup.ID], i)
			}
		}
		if len(refs[lookup.ID]) == 0 {
			always[lookup.ID] = true
		}
	}
	return refs, always
}

func lookupTokens(lookup LookupDefinition) []string {
	tokens := []string{lookup.ID, "store." + lookup.ID, "store_" + lookup.ID}
	for _, path := range lookup.Outputs {
		if path != "" {
			tokens = append(tokens, path)
		}
	}
	return tokens
}

func ruleUsesAnyLookupToken(rule Rule, tokens []string) bool {
	if expressionUsesAny(rule.Condition, tokens) {
		return true
	}
	for _, adder := range rule.Risk.Adders {
		if expressionUsesAny(adder.Condition, tokens) || expressionUsesAny(adder.Field, tokens) {
			return true
		}
	}
	for _, severity := range rule.Severity {
		if expressionUsesAny(severity.Condition, tokens) {
			return true
		}
	}
	return false
}

func expressionUsesAny(expr string, tokens []string) bool {
	if expr == "" {
		return false
	}
	for _, token := range tokens {
		if token != "" && strings.Contains(expr, token) {
			return true
		}
	}
	return false
}

func rulesUseStoreFunctions(rules []Rule) bool {
	for _, rule := range rules {
		if usesStoreFunction(rule.Condition) {
			return true
		}
		for _, adder := range rule.Risk.Adders {
			if usesStoreFunction(adder.Condition) {
				return true
			}
		}
		for _, severity := range rule.Severity {
			if usesStoreFunction(severity.Condition) {
				return true
			}
		}
	}
	return false
}

func usesStoreFunction(expr string) bool {
	return strings.Contains(expr, "store.") || strings.Contains(expr, "store_")
}

func detectorsNeedFacts(detectors []Detector) bool {
	for _, detector := range detectors {
		switch detector.(type) {
		case HeaderAnomalyDetector, SensitiveEndpointDetector, ReplayDetector, RateDetector, SessionDriftDetector, BusinessAnomalyDetector, AbuseDetector:
			continue
		default:
			return true
		}
	}
	return false
}

func (g *Guard) publishSnapshotLocked() {
	g.snapshot.Store(newRuntimeSnapshot(g))
}

func copyActions(in map[string]ActionDefinition) map[string]ActionDefinition {
	out := make(map[string]ActionDefinition, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyActionHandlers(in map[string]ActionExecutor) map[string]ActionExecutor {
	out := make(map[string]ActionExecutor, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func buildRuleIndex(rules []Rule) ruleIndex {
	idx := ruleIndex{events: map[string]eventRuleIndex{}}
	for i := range rules {
		rule := &rules[i]
		if len(rule.Triggers) == 0 {
			addRuleToEventIndex(&idx.allEvents, i, rule)
			continue
		}
		for _, eventType := range rule.Triggers {
			bucket := idx.events[eventType]
			addRuleToEventIndex(&bucket, i, rule)
			idx.events[eventType] = bucket
		}
	}
	return idx
}

func addRuleToEventIndex(idx *eventRuleIndex, ruleIndex int, rule *Rule) {
	if len(rule.Scope.Paths) == 0 {
		idx.noPath = append(idx.noPath, ruleIndex)
		return
	}
	for _, pattern := range rule.scopePaths {
		switch pattern.kind {
		case pathPatternAny:
			idx.anyPath = append(idx.anyPath, ruleIndex)
		case pathPatternExact:
			if idx.exact == nil {
				idx.exact = map[string][]int{}
			}
			idx.exact[pattern.raw] = append(idx.exact[pattern.raw], ruleIndex)
		case pathPatternPrefix:
			idx.prefixes = append(idx.prefixes, pathIndexedRule{index: ruleIndex, pattern: pattern})
		case pathPatternGlob:
			idx.globs = append(idx.globs, pathIndexedRule{index: ruleIndex, pattern: pattern})
		case pathPatternRoute:
			idx.routes = append(idx.routes, pathIndexedRule{index: ruleIndex, pattern: pattern})
		default:
			if idx.exact == nil {
				idx.exact = map[string][]int{}
			}
			idx.exact[pattern.raw] = append(idx.exact[pattern.raw], ruleIndex)
		}
	}
}

func (idx ruleIndex) candidates(eventTypes []string, path string, totalRules int) []int {
	if totalRules == 0 {
		return nil
	}
	seen := make(map[int]bool, 16)
	out := make([]int, 0, 16)
	addEventCandidates(idx.allEvents, path, seen, &out)
	for _, eventType := range eventTypes {
		addEventCandidates(idx.events[eventType], path, seen, &out)
	}
	sort.Ints(out)
	return out
}

func (idx ruleIndex) candidatesFor(eventTypes []string, sec *Context, rules []Rule) []int {
	return idx.candidatesForIndexed(eventTypes, sec, rules, true)
}

func (idx ruleIndex) candidatesForIndexed(eventTypes []string, sec *Context, rules []Rule, indexed bool) []int {
	if !indexed {
		out := make([]int, len(rules))
		for i := range rules {
			out[i] = i
		}
		return out
	}
	path := ""
	if sec != nil {
		path = sec.Request.Path
	}
	candidates := idx.candidates(eventTypes, path, len(rules))
	if sec == nil || len(candidates) == 0 {
		return candidates
	}
	out := candidates[:0]
	for _, candidate := range candidates {
		if candidate < 0 || candidate >= len(rules) {
			continue
		}
		if quickScopeCandidate(&rules[candidate], sec) {
			out = append(out, candidate)
		}
	}
	return out
}

func quickScopeCandidate(rule *Rule, sec *Context) bool {
	if rule == nil || sec == nil {
		return true
	}
	scope := rule.Scope
	if len(scope.Methods) > 0 && !scopeAllows(scope.Methods, sec.Request.Method) {
		return false
	}
	if len(scope.Tenants) > 0 && !scopeAllows(scope.Tenants, sec.Tenant.ID, sec.Identity.Tenant) {
		return false
	}
	if len(scope.Roles) > 0 && !scopeAllows(scope.Roles, sec.Identity.Role, sec.Identity.Roles...) {
		return false
	}
	return true
}

func addEventCandidates(idx eventRuleIndex, path string, seen map[int]bool, out *[]int) {
	addRuleIndexes(idx.noPath, seen, out)
	addRuleIndexes(idx.anyPath, seen, out)
	if len(idx.exact) > 0 {
		addRuleIndexes(idx.exact[path], seen, out)
	}
	for _, item := range idx.prefixes {
		if matched, _ := item.pattern.Match(path); matched {
			addRuleIndex(item.index, seen, out)
		}
	}
	for _, item := range idx.routes {
		if matched, _ := item.pattern.Match(path); matched {
			addRuleIndex(item.index, seen, out)
		}
	}
	for _, item := range idx.globs {
		if matched, _ := item.pattern.Match(path); matched {
			addRuleIndex(item.index, seen, out)
		}
	}
}

func addRuleIndexes(indexes []int, seen map[int]bool, out *[]int) {
	for _, index := range indexes {
		addRuleIndex(index, seen, out)
	}
}

func addRuleIndex(index int, seen map[int]bool, out *[]int) {
	if seen[index] {
		return
	}
	seen[index] = true
	*out = append(*out, index)
}
