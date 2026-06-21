package bcl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/oarkflow/tcpguard"
)

const bclRefArgSep = "\x1f"

func LoadTCPGuardBundleFile(ctx context.Context, path string) (tcpguard.Bundle, error) {
	return loadTCPGuardBundleFile(ctx, path, map[string]bool{})
}

func loadTCPGuardBundleFile(ctx context.Context, path string, seen map[string]bool) (tcpguard.Bundle, error) {
	clean, err := filepath.Abs(path)
	if err == nil {
		path = clean
	}
	if seen[path] {
		return tcpguard.Bundle{}, ctx.Err()
	}
	seen[path] = true
	data, err := os.ReadFile(path)
	if err != nil {
		return tcpguard.Bundle{}, err
	}
	bundle, err := ParseTCPGuardBundle(data)
	if err != nil {
		return tcpguard.Bundle{}, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	bundle.BaseDir = base
	normalizeTCPGuardBundlePaths(&bundle, base)
	for _, include := range findTCPGuardIncludes(data) {
		matches, _ := filepath.Glob(filepath.Join(base, include))
		sort.Strings(matches)
		for _, match := range matches {
			child, err := loadTCPGuardBundleFile(ctx, match, seen)
			if err != nil {
				return tcpguard.Bundle{}, err
			}
			mergeTCPGuardBundle(&bundle, child)
		}
	}
	return bundle, ctx.Err()
}

func LoadTCPGuardBundleDir(ctx context.Context, dir string) (tcpguard.Bundle, error) {
	var bundle tcpguard.Bundle
	bundle.BaseDir = dir
	var files []string
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(path, ".bcl") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return bundle, err
	}
	sort.Strings(files)
	seen := map[string]bool{}
	for _, path := range files {
		child, err := loadTCPGuardBundleFile(ctx, path, seen)
		if err != nil {
			return bundle, err
		}
		mergeTCPGuardBundle(&bundle, child)
	}
	return bundle, ctx.Err()
}

func ParseTCPGuardBundle(data []byte) (tcpguard.Bundle, error) {
	p := tcpGuardParser{lines: scanTCPGuardLines(data)}
	return p.parse()
}

type tcpGuardParser struct {
	lines []string
	i     int
	out   tcpguard.Bundle
}

func (p *tcpGuardParser) parse() (tcpguard.Bundle, error) {
	for p.i < len(p.lines) {
		line := p.line()
		switch firstTCPGuardWord(line) {
		case "guard":
			if err := p.parseGuard(); err != nil {
				return p.out, err
			}
		case "pack":
			if err := p.parsePack(); err != nil {
				return p.out, err
			}
		case "rule":
			rule, err := p.parseRule()
			if err != nil {
				return p.out, err
			}
			p.out.Rules = append(p.out.Rules, rule)
		case "datasource":
			p.out.DataSources = append(p.out.DataSources, p.parseDataSource())
		case "lookup":
			p.out.Lookups = append(p.out.Lookups, p.parseLookup())
		case "action":
			action, err := p.parseAction()
			if err != nil {
				return p.out, err
			}
			p.out.Actions = append(p.out.Actions, action)
		case "trigger":
			trigger, err := p.parseTrigger()
			if err != nil {
				return p.out, err
			}
			p.out.DerivedEvents = append(p.out.DerivedEvents, trigger)
		case "detector":
			p.out.Detectors = append(p.out.Detectors, p.parseDetector())
		case "enricher":
			p.out.Enrichers = append(p.out.Enrichers, p.parseEnricher())
		case "intel":
			p.out.IntelFeeds = append(p.out.IntelFeeds, p.parseIntel())
		case "baseline":
			p.out.Baselines = append(p.out.Baselines, p.parseBaseline())
		case "threat_model":
			p.out.ThreatModels = append(p.out.ThreatModels, p.parseThreatModel())
		case "policy_safety":
			if err := p.parseSafety(); err != nil {
				return p.out, err
			}
		default:
			p.i++
		}
	}
	return p.out, nil
}

func (p *tcpGuardParser) parsePack() error {
	if p.out.Name == "" {
		p.out.Name = quotedTCPGuardName(p.line())
	}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return nil
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "version":
				p.out.Version = trimTCPGuardQuote(value)
			case "mode":
				p.out.Mode = tcpguard.Mode(value)
			}
		}
		p.i++
	}
	return nil
}

func (p *tcpGuardParser) parseGuard() error {
	if p.out.Name == "" {
		p.out.Name = quotedTCPGuardName(p.line())
	}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return nil
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "mode":
				p.out.Mode = tcpguard.Mode(value)
			case "version":
				p.out.Version = trimTCPGuardQuote(value)
			case "timezone":
				p.out.Timezone = trimTCPGuardQuote(value)
			}
		}
		if isTCPGuardBlock(line, "authz") {
			p.out.Authz = p.parseAuthz()
			continue
		}
		p.i++
	}
	return nil
}

func (p *tcpGuardParser) parseRule() (tcpguard.Rule, error) {
	rule := tcpguard.Rule{ID: quotedTCPGuardName(p.line()), Status: tcpguard.RuleActive, Risk: tcpguard.RiskSpec{Max: 100}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return rule, nil
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "name":
				rule.Name = trimTCPGuardQuote(strings.TrimSpace(line[len(key):]))
			case "status":
				rule.Status = tcpguard.RuleStatus(value)
			case "priority":
				rule.Priority, _ = strconv.Atoi(value)
			case "version":
				rule.Version, _ = strconv.Atoi(value)
			case "owner":
				rule.Owner = trimTCPGuardQuote(value)
			case "authz_policy":
				rule.AuthzPolicy = trimTCPGuardQuote(value)
			}
		}
		switch firstTCPGuardWord(line) {
		case "scope":
			rule.Scope = p.parseScope()
		case "trigger":
			rule.Triggers, rule.Sequence = p.parseRuleTrigger()
		case "when":
			rule.Condition = p.parseConditionBlock()
		case "risk":
			rule.Risk = p.parseRisk()
		case "severity":
			rule.Severity = p.parseSeverity()
		case "actions":
			rule.Actions = p.parseActions()
		case "cooldown":
			rule.Cooldown = p.parseCooldown()
		case "approval":
			rule.Approval = p.parseApproval()
		default:
			p.i++
		}
	}
	return rule, nil
}

func (p *tcpGuardParser) parseAuthz() tcpguard.AuthzConfig {
	cfg := tcpguard.AuthzConfig{Strict: true, ErrorPolicy: tcpguard.AuthzErrorDeny}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return cfg
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "file":
				cfg.File = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "strict":
				cfg.Strict = value == "true"
			case "enforce_http":
				cfg.EnforceHTTP = value == "true"
			case "timeout":
				cfg.Timeout, _ = time.ParseDuration(value)
			case "error_policy":
				cfg.ErrorPolicy = tcpguard.AuthzErrorPolicy(trimTCPGuardQuote(value))
			}
		}
		p.i++
	}
	return cfg
}

func (p *tcpGuardParser) parseScope() tcpguard.Scope {
	var scope tcpguard.Scope
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return scope
		}
		switch firstTCPGuardWord(line) {
		case "tenants":
			scope.Tenants = parseTCPGuardList(line)
		case "roles":
			scope.Roles = parseTCPGuardList(line)
		case "methods":
			scope.Methods = parseTCPGuardList(line)
		case "paths":
			scope.Paths = parseTCPGuardList(line)
		}
		p.i++
	}
	return scope
}

func (p *tcpGuardParser) parseRuleTrigger() ([]string, *tcpguard.SequenceTrigger) {
	var triggers []string
	var sequence *tcpguard.SequenceTrigger
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return triggers, sequence
		}
		key, value, rest, ok := cutTCPGuardFields2(line)
		if ok && key == "on" {
			triggers = append(triggers, value)
		}
		third, _, hasThird := cutTCPGuardField(rest)
		if ok && hasThird && key == "sequence" && value == "within" {
			d, _ := time.ParseDuration(third)
			sequence = &tcpguard.SequenceTrigger{Within: d}
			p.i++
			for p.i < len(p.lines) {
				inner := p.line()
				if inner == "}" {
					p.i++
					break
				}
				event, innerRest, ok := cutTCPGuardField(inner)
				if ok {
					step := tcpguard.SequenceStep{Event: event}
					if countValue, ok := tcpGuardValueAfterWord(innerRest, "count"); ok {
						step.Count, _ = strconv.Atoi(countValue)
					}
					sequence.Steps = append(sequence.Steps, step)
				}
				p.i++
			}
			continue
		}
		p.i++
	}
	return triggers, sequence
}

func (p *tcpGuardParser) parseConditionBlock() string {
	p.i++
	return p.parseConditionGroup("all")
}

func (p *tcpGuardParser) parseConditionGroup(mode string) string {
	var b strings.Builder
	terms := 0
	for p.i < len(p.lines) {
		line := strings.TrimSpace(p.line())
		line = strings.TrimSpace(strings.TrimSuffix(line, "{"))
		switch line {
		case "}":
			p.i++
			return finishTCPGuardConditionGroup(mode, b.String(), terms)
		case "all", "any", "not":
			p.i++
			expr := p.parseConditionGroup(line)
			if expr != "" {
				appendTCPGuardConditionTerm(&b, mode, terms, expr)
				terms++
			}
			continue
		default:
			line = strings.TrimSpace(strings.TrimSuffix(line, "}"))
			if line != "" {
				appendTCPGuardConditionTerm(&b, mode, terms, normalizeTCPGuardCondition(line))
				terms++
			}
		}
		p.i++
	}
	return finishTCPGuardConditionGroup(mode, b.String(), terms)
}

func (p *tcpGuardParser) parseRisk() tcpguard.RiskSpec {
	risk := tcpguard.RiskSpec{Max: 100}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return risk
		}
		key, value, rest, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "base":
				risk.Base, _ = strconv.ParseFloat(value, 64)
			case "max":
				risk.Max, _ = strconv.ParseFloat(value, 64)
			case "decay":
				risk.Decay, _ = time.ParseDuration(value)
			case "profile":
				risk.Profile = parseTCPGuardList(line)
			case "add":
				value, _ := strconv.ParseFloat(value, 64)
				cond := ""
				if when := tailTCPGuardAfterWord(rest, "when"); when != "" {
					cond = when
				}
				risk.Adders = append(risk.Adders, tcpguard.RiskAdder{Value: value, Condition: cond})
			}
		}
		p.i++
	}
	return risk
}

func (p *tcpGuardParser) parseSeverity() []tcpguard.SeverityRule {
	var out []tcpguard.SeverityRule
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return out
		}
		severity, rest, ok := cutTCPGuardField(line)
		if ok {
			if when := tailTCPGuardAfterWord(rest, "when"); when != "" {
				out = append(out, tcpguard.SeverityRule{Severity: tcpguard.Severity(severity), Condition: when})
			}
		}
		p.i++
	}
	return out
}

func (p *tcpGuardParser) parseActions() map[tcpguard.Severity][]tcpguard.ActionRef {
	out := map[tcpguard.Severity][]tcpguard.ActionRef{}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return out
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok && value == "{" && strings.HasSuffix(line, "{") {
			severity := tcpguard.Severity(key)
			p.i++
			for p.i < len(p.lines) {
				inner := p.line()
				if inner == "}" {
					p.i++
					break
				}
				key, value, rest, ok := cutTCPGuardFields2(inner)
				if ok && key == "run" {
					ref := tcpguard.ActionRef{ID: trimTCPGuardQuote(value)}
					if strings.TrimSpace(rest) != "" {
						ref.Args = strings.Fields(rest)
					}
					out[severity] = append(out[severity], ref)
				}
				p.i++
			}
			continue
		}
		p.i++
	}
	return out
}

func (p *tcpGuardParser) parseCooldown() tcpguard.Cooldown {
	var c tcpguard.Cooldown
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return c
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			if key == "key" {
				c.Key = value
			}
			if key == "duration" {
				c.Duration, _ = time.ParseDuration(value)
			}
		}
		p.i++
	}
	return c
}

func (p *tcpGuardParser) parseApproval() tcpguard.Approval {
	var a tcpguard.Approval
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return a
		}
		if firstTCPGuardWord(line) == "required" {
			a.Required = strings.Contains(line, "true")
		}
		if firstTCPGuardWord(line) == "approvers" {
			a.Approvers = parseTCPGuardList(line)
		}
		p.i++
	}
	return a
}

func (p *tcpGuardParser) parseAction() (tcpguard.ActionDefinition, error) {
	action := tcpguard.ActionDefinition{
		ID:     quotedTCPGuardName(p.line()),
		Method: "POST",
		Request: tcpguard.ActionRequest{
			Method: "POST",
		},
	}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return action, nil
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "type":
				action.Type = value
			case "endpoint":
				action.Endpoint = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "method":
				action.Method = value
			case "provider":
				action.Provider = value
			case "subject":
				action.Subject = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "timeout":
				action.Timeout, _ = time.ParseDuration(value)
			case "success_codes":
				action.SuccessCodes = parseTCPGuardList(line)
			case "retry_on_codes":
				action.RetryOnCodes = parseTCPGuardList(line)
			case "allow_private_url":
				action.AllowPrivateURL = value == "true"
			}
		}
		switch firstTCPGuardWord(line) {
		case "headers":
			action.Request.Headers = p.parseStringMapBlock()
			action.Headers = action.Request.Headers
			continue
		case "body":
			template, body, include, fields := p.parseBodyBlock()
			action.Request.BodyTemplate = template
			action.BodyTemplate = template
			action.Request.Body = body
			action.Request.Include = include
			action.Request.Fields = fields
			continue
		case "payload":
			_, body, include, fields := p.parseBodyBlock()
			action.Request.Body = body
			action.Request.Include = include
			action.Request.Fields = fields
			continue
		case "request":
			req := p.parseRequestBlock()
			action.Request = req
			action.Endpoint = firstTCPGuardNonEmpty(action.Endpoint, req.Endpoint)
			action.Method = firstTCPGuardNonEmpty(action.Method, req.Method)
			action.Headers = req.Headers
			action.BodyTemplate = req.BodyTemplate
			continue
		case "retry":
			action.Retry = p.parseRetryBlock()
			continue
		case "idempotency":
			action.Idempotency = p.parseIdempotencyBlock()
			continue
		}
		p.i++
	}
	return action, nil
}

func (p *tcpGuardParser) parseRetryBlock() tcpguard.RetryPolicy {
	var retry tcpguard.RetryPolicy
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return retry
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "attempts":
				retry.Attempts, _ = strconv.Atoi(value)
			case "backoff":
				retry.Backoff = value
			case "jitter":
				retry.Jitter = value == "true"
			}
		}
		p.i++
	}
	return retry
}

func (p *tcpGuardParser) parseIdempotencyBlock() tcpguard.IdempotencyPolicy {
	var id tcpguard.IdempotencyPolicy
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return id
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "header":
				id.Header = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "key":
				id.Key = tailTCPGuardAfterFirst(line)
			default:
				_ = value
			}
		}
		p.i++
	}
	return id
}

func (p *tcpGuardParser) parseTrigger() (tcpguard.DerivedTrigger, error) {
	trigger := tcpguard.DerivedTrigger{ID: quotedTCPGuardName(p.line())}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return trigger, nil
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "source":
				trigger.Source = value
			case "emit":
				trigger.Emit = trimTCPGuardQuote(value)
			}
		}
		if firstTCPGuardWord(line) == "when" {
			trigger.Condition = p.parseConditionBlock()
			continue
		}
		p.i++
	}
	return trigger, nil
}

func (p *tcpGuardParser) parseDataSource() tcpguard.DataSourceDefinition {
	def := tcpguard.DataSourceDefinition{ID: quotedTCPGuardName(p.line()), Method: "POST", Headers: map[string]string{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "type":
				def.Type = value
			case "prefix":
				def.Prefix = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "path":
				def.Path = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "key":
				def.Key = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "url":
				def.URL = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "method":
				def.Method = value
			case "driver":
				def.Driver = value
			case "dsn":
				def.DSN = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "timeout":
				def.Timeout, _ = time.ParseDuration(value)
			case "cache_ttl":
				def.CacheTTL, _ = time.ParseDuration(value)
			case "cache_refresh":
				def.CacheRefresh, _ = time.ParseDuration(value)
			case "watch":
				def.Watch = value == "true"
			case "allow_private_url":
				def.AllowPrivateURL = value == "true"
			}
		}
		if firstTCPGuardWord(line) == "headers" {
			def.Headers = p.parseStringMapBlock()
			continue
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseLookup() tcpguard.LookupDefinition {
	def := tcpguard.LookupDefinition{ID: quotedTCPGuardName(p.line()), Mode: "function", Params: map[string]string{}, Outputs: map[string]string{}, Fallback: tcpguard.LookupFallback{Policy: tcpguard.LookupFallbackAllow}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "source":
				def.Source = trimTCPGuardQuote(value)
			case "mode":
				def.Mode = value
			case "key":
				def.Key = tailTCPGuardAfterFirst(line)
			case "query":
				def.Query = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "timeout":
				def.Timeout, _ = time.ParseDuration(value)
			}
		}
		switch firstTCPGuardWord(line) {
		case "params":
			def.Params = p.parseLookupParams()
			continue
		case "output":
			def.Outputs = p.parseLookupOutput()
			continue
		case "fallback":
			def.Fallback = p.parseLookupFallback()
			continue
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseLookupParams() map[string]string {
	out := map[string]string{}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return out
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[fields[0]] = strings.Join(fields[1:], " ")
		}
		p.i++
	}
	return out
}

func (p *tcpGuardParser) parseLookupOutput() map[string]string {
	out := map[string]string{}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return out
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "map" && fields[2] == "to" {
			out[trimTCPGuardQuote(fields[1])] = fields[3]
		}
		p.i++
	}
	return out
}

func (p *tcpGuardParser) parseLookupFallback() tcpguard.LookupFallback {
	fallback := tcpguard.LookupFallback{Policy: tcpguard.LookupFallbackAllow, Value: map[string]any{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return fallback
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "policy":
				fallback.Policy = tcpguard.LookupFallbackPolicy(fields[1])
			case "reason":
				fallback.Reason = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "field":
				if len(fields) >= 3 {
					fallback.Value[fields[1]] = parseTCPGuardValue(strings.Join(fields[2:], " "))
				}
			case "value":
				if strings.HasSuffix(line, "{") || line == "value {" {
					p.i++
					for p.i < len(p.lines) {
						inner := p.line()
						if inner == "}" {
							p.i++
							break
						}
						parts := strings.Fields(inner)
						if len(parts) >= 2 {
							fallback.Value[parts[0]] = parseTCPGuardValue(strings.Join(parts[1:], " "))
						}
						p.i++
					}
					continue
				}
			}
		}
		p.i++
	}
	return fallback
}

func (p *tcpGuardParser) parseSafety() error {
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return nil
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "max_rule_eval_time":
				p.out.Safety.MaxRuleEvalTime, _ = time.ParseDuration(fields[1])
			case "max_detector_timeout":
				p.out.Safety.MaxDetectorTimeout, _ = time.ParseDuration(fields[1])
			case "max_lookup_timeout":
				p.out.Safety.MaxLookupTimeout, _ = time.ParseDuration(fields[1])
			case "max_action_timeout":
				p.out.Safety.MaxActionTimeout, _ = time.ParseDuration(fields[1])
			case "max_actions_per_rule":
				p.out.Safety.MaxActionsPerRule, _ = strconv.Atoi(fields[1])
			case "max_lookups_per_eval":
				p.out.Safety.MaxLookupsPerEval, _ = strconv.Atoi(fields[1])
			case "max_retry_count":
				p.out.Safety.MaxRetryCount, _ = strconv.Atoi(fields[1])
			case "max_webhook_timeout":
				p.out.Safety.MaxWebhookTimeout, _ = time.ParseDuration(fields[1])
			case "require_signature":
				p.out.Safety.RequireSignature = fields[1] == "true"
			case "require_approval_for":
				p.out.Safety.RequireApprovalFor = parseTCPGuardList(line)
			case "action_allowlist":
				p.out.Safety.ActionAllowlist = parseTCPGuardList(line)
			case "allow_datasource_types":
				p.out.Safety.AllowedDataSources = parseTCPGuardList(line)
			case "require_approval_for_datasource":
				p.out.Safety.ApprovalDataSource = parseTCPGuardList(line)
			case "command_enabled":
				p.out.Safety.CommandEnabled = fields[1] == "true"
			}
		}
		p.i++
	}
	return nil
}

func (p *tcpGuardParser) parseDetector() tcpguard.DetectorDefinition {
	def := tcpguard.DetectorDefinition{ID: quotedTCPGuardName(p.line()), Method: "POST", Fields: map[string]any{}, Outputs: map[string]any{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "type":
				def.Type = fields[1]
			case "input":
				def.Input = fields[1]
			case "endpoint":
				def.Endpoint = trimTCPGuardQuote(fields[1])
			case "method":
				def.Method = fields[1]
			case "timeout":
				def.Timeout, _ = time.ParseDuration(fields[1])
			case "fallback":
				def.Fallback = fields[1]
			case "window":
				if d, err := time.ParseDuration(fields[1]); err == nil {
					def.Fields["window"] = d
				}
			case "auth_ip_failure_threshold", "auth_user_failure_threshold", "password_spray_user_threshold", "api_key_ip_threshold", "api_key_user_threshold", "scan_path_threshold", "export_threshold", "function_invoke_threshold", "user_agent_rotation_threshold", "tenant_user_threshold", "account_enumeration_threshold", "large_body_threshold":
				n, _ := strconv.ParseInt(fields[1], 10, 64)
				def.Fields[fields[0]] = n
			case "payment_user_amount_threshold", "payment_tenant_amount_threshold", "profile_risk_threshold":
				n, _ := strconv.ParseFloat(fields[1], 64)
				def.Fields[fields[0]] = n
			case "field":
				if len(fields) >= 3 {
					def.Outputs[fields[1]] = parseTCPGuardValue(strings.Join(fields[2:], " "))
				}
			}
		}
		switch firstTCPGuardWord(line) {
		case "finding":
			def.Findings = append(def.Findings, p.parseDetectorFinding())
			continue
		case "output":
			for key, value := range p.parseOutputBlock() {
				def.Outputs[key] = value
			}
			continue
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseDetectorFinding() tcpguard.DetectorFindingDefinition {
	start := p.line()
	def := tcpguard.DetectorFindingDefinition{ID: quotedTCPGuardName(start), Fields: map[string]any{}}
	if def.ID == "" {
		fields := strings.Fields(start)
		if len(fields) >= 2 {
			def.ID = trimTCPGuardQuote(fields[1])
		}
	}
	if strings.Contains(start, " when") {
		p.i++
		def.Condition = p.parseConditionGroup("all")
		return def
	}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "risk":
				def.Risk, _ = strconv.ParseFloat(fields[1], 64)
			case "message":
				def.Message = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "field":
				if len(fields) >= 3 {
					def.Fields[fields[1]] = parseTCPGuardValue(strings.Join(fields[2:], " "))
				}
			}
		}
		if firstTCPGuardWord(line) == "when" {
			def.Condition = p.parseConditionBlock()
			continue
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseOutputBlock() map[string]any {
	out := map[string]any{}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return out
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "field" {
			out[fields[1]] = parseTCPGuardValue(strings.Join(fields[2:], " "))
		}
		p.i++
	}
	return out
}

func (p *tcpGuardParser) parseEnricher() tcpguard.EnricherDefinition {
	def := tcpguard.EnricherDefinition{ID: quotedTCPGuardName(p.line()), Fields: map[string]string{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "type":
				def.Type = fields[1]
			case "source":
				def.Source = strings.Join(fields[1:], " ")
			case "key":
				def.Key = fields[1]
			case "map":
				if len(fields) >= 4 && fields[2] == "to" {
					def.Fields[trimTCPGuardQuote(fields[1])] = fields[3]
				}
			}
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseIntel() tcpguard.IntelDefinition {
	def := tcpguard.IntelDefinition{ID: quotedTCPGuardName(p.line()), Fields: map[string]any{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "type":
				def.Type = fields[1]
			case "path":
				def.Path = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "url":
				def.URL = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "refresh":
				def.Refresh, _ = time.ParseDuration(fields[1])
			case "match":
				def.Match = fields[1]
			case "field":
				if len(fields) >= 3 {
					def.Fields[fields[1]] = parseTCPGuardValue(strings.Join(fields[2:], " "))
				}
			}
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseBaseline() tcpguard.BaselineDefinition {
	def := tcpguard.BaselineDefinition{ID: quotedTCPGuardName(p.line()), Fields: map[string]string{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "entity":
				def.Entity = fields[1]
			case "observe":
				def.Observe = fields[1]
			case "window":
				def.Window, _ = time.ParseDuration(fields[1])
			case "min_samples":
				def.MinSamples, _ = strconv.Atoi(fields[1])
			case "field":
				if len(fields) >= 3 {
					def.Fields[fields[1]] = fields[2]
				}
			}
		}
		if firstTCPGuardWord(line) == "fields" {
			p.i++
			for p.i < len(p.lines) {
				inner := p.line()
				if inner == "}" {
					p.i++
					break
				}
				parts := strings.Fields(inner)
				if len(parts) >= 2 {
					def.Fields[parts[0]] = parts[1]
				}
				p.i++
			}
			continue
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseThreatModel() tcpguard.ThreatModelDefinition {
	def := tcpguard.ThreatModelDefinition{ID: quotedTCPGuardName(p.line()), Categories: map[string][]string{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return def
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "category" {
			category := fields[1]
			p.i++
			var findings []string
			for p.i < len(p.lines) {
				inner := p.line()
				if inner == "}" {
					p.i++
					break
				}
				if firstTCPGuardWord(inner) == "findings" {
					findings = parseTCPGuardList(inner)
				}
				p.i++
			}
			def.Categories[category] = findings
			continue
		}
		p.i++
	}
	return def
}

func (p *tcpGuardParser) parseStringMapBlock() map[string]string {
	out := map[string]string{}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return out
		}
		key, value, ok := parseTCPGuardPair(line)
		if ok {
			out[key] = value
		}
		p.i++
	}
	return out
}

func (p *tcpGuardParser) parseBodyBlock() (string, map[string]any, map[string]string, map[string]any) {
	var body map[string]any
	var include map[string]string
	var fields map[string]any
	var template string
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return template, body, include, fields
		}
		key, value, rest, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "template":
				template = trimTCPGuardQuote(tailTCPGuardAfterFirst(line))
			case "include":
				path := value
				alias := strings.ReplaceAll(path, ".", "_")
				as, aliasValue, _, ok := cutTCPGuardFields2(rest)
				if ok && as == "as" {
					alias = trimTCPGuardQuote(aliasValue)
				}
				if include == nil {
					include = map[string]string{}
				}
				include[alias] = path
			case "field":
				if strings.TrimSpace(rest) != "" {
					if fields == nil {
						fields = map[string]any{}
					}
					fields[value] = parseTCPGuardValue(rest)
				}
			default:
				if body == nil {
					body = map[string]any{}
				}
				body[key] = parseTCPGuardValue(strings.TrimSpace(line[len(key):]))
			}
		}
		p.i++
	}
	return template, body, include, fields
}

func (p *tcpGuardParser) parseRequestBlock() tcpguard.ActionRequest {
	req := tcpguard.ActionRequest{Method: "POST"}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return req
		}
		key, value, _, ok := cutTCPGuardFields2(line)
		if ok {
			switch key {
			case "endpoint":
				req.Endpoint = parseTCPGuardStringValue(tailTCPGuardAfterFirst(line))
			case "method":
				req.Method = value
			case "headers":
				req.Headers = p.parseStringMapBlock()
				continue
			case "body", "payload":
				template, body, include, fields := p.parseBodyBlock()
				req.BodyTemplate = template
				req.Body = body
				req.Include = include
				req.Fields = fields
				continue
			}
		}
		p.i++
	}
	return req
}

func (p *tcpGuardParser) line() string { return p.lines[p.i] }

func scanTCPGuardLines(data []byte) []string {
	out := make([]string, 0, countTCPGuardLines(data))
	for len(data) > 0 {
		line := data
		if idx := bytesIndexByte(data, '\n'); idx >= 0 {
			line = data[:idx]
			data = data[idx+1:]
		} else {
			data = nil
		}
		line = trimTCPGuardBytes(line)
		if len(line) == 0 || line[0] == '#' || bytesHasPrefix(line, "//") {
			continue
		}
		out = append(out, unsafeTCPGuardString(line))
	}
	return out
}

func countTCPGuardLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := 1
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	return n
}

func trimTCPGuardBytes(data []byte) []byte {
	for len(data) > 0 && isTCPGuardSpace(data[0]) {
		data = data[1:]
	}
	for len(data) > 0 && isTCPGuardSpace(data[len(data)-1]) {
		data = data[:len(data)-1]
	}
	return data
}

func bytesIndexByte(data []byte, c byte) int {
	for i, b := range data {
		if b == c {
			return i
		}
	}
	return -1
}

func bytesHasPrefix(data []byte, prefix string) bool {
	if len(data) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

func isTCPGuardSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func unsafeTCPGuardString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(data), len(data))
}

func hasTCPGuardPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}

func firstTCPGuardWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if isTCPGuardSpace(s[i]) || s[i] == '{' || s[i] == '}' {
			return s[:i]
		}
	}
	return s
}

func isTCPGuardBlock(line, word string) bool {
	return firstTCPGuardWord(line) == word
}

func normalizeTCPGuardCondition(s string) string {
	if converted, ok := normalizeTCPGuardWildcardMatch(s); ok {
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

func appendTCPGuardConditionTerm(b *strings.Builder, mode string, terms int, expr string) {
	if terms == 0 {
		b.WriteString(expr)
		return
	}
	if mode == "any" {
		b.WriteString(" or ")
	} else {
		b.WriteString(" and ")
	}
	b.WriteString(expr)
}

func finishTCPGuardConditionGroup(mode, expr string, terms int) string {
	if terms == 0 {
		return ""
	}
	if mode == "not" {
		return "not (" + expr + ")"
	}
	if terms == 1 {
		return expr
	}
	return "(" + expr + ")"
}

func normalizeTCPGuardWildcardMatch(s string) (string, bool) {
	field, rest, ok := cutTCPGuardField(strings.TrimSpace(s))
	if !ok {
		return "", false
	}
	op, rest, ok := cutTCPGuardField(rest)
	if !ok || op != "matches" {
		return "", false
	}
	pattern, rest, ok := cutTCPGuardField(rest)
	if !ok || strings.TrimSpace(rest) != "" {
		return "", false
	}
	return "wildcard_match(" + field + ", " + pattern + ")", true
}

func quotedTCPGuardName(line string) string {
	start := strings.IndexByte(line, '"')
	if start < 0 {
		_, rest, ok := cutTCPGuardField(line)
		if !ok {
			return ""
		}
		name, _, ok := cutTCPGuardField(rest)
		if !ok {
			return ""
		}
		return trimTCPGuardQuote(name)
	}
	end := strings.IndexByte(line[start+1:], '"')
	if end < 0 {
		return ""
	}
	return line[start+1 : start+1+end]
}

func trimTCPGuardQuote(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"`)
}

func parseTCPGuardPair(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if len(line) > 0 && line[0] == '"' {
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		key := line[1 : 1+end]
		value := strings.TrimSpace(line[1+end+1:])
		return key, parseTCPGuardStringValue(value), value != ""
	}
	key, value, ok := cutTCPGuardField(line)
	if !ok {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	return key, parseTCPGuardStringValue(value), true
}

func cutTCPGuardField(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if s[0] == '"' || s[0] == '\'' {
		quote := s[0]
		escaped := false
		for i := 1; i < len(s); i++ {
			switch {
			case escaped:
				escaped = false
			case s[i] == '\\':
				escaped = true
			case s[i] == quote:
				return s[:i+1], s[i+1:], true
			}
		}
		return "", "", false
	}
	for i := 0; i < len(s); i++ {
		if isTCPGuardSpace(s[i]) {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", true
}

func cutTCPGuardFields2(s string) (string, string, string, bool) {
	first, rest, ok := cutTCPGuardField(s)
	if !ok {
		return "", "", "", false
	}
	second, rest, ok := cutTCPGuardField(rest)
	if !ok {
		return "", "", "", false
	}
	return first, second, rest, true
}

func tailTCPGuardAfterFirst(s string) string {
	_, rest, ok := cutTCPGuardField(s)
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

func tailTCPGuardAfterWord(s, word string) string {
	for {
		field, rest, ok := cutTCPGuardField(s)
		if !ok {
			return ""
		}
		if field == word {
			return strings.TrimSpace(rest)
		}
		s = rest
	}
}

func tcpGuardValueAfterWord(s, word string) (string, bool) {
	tail := tailTCPGuardAfterWord(s, word)
	if tail == "" {
		return "", false
	}
	value, _, ok := cutTCPGuardField(tail)
	return value, ok
}

func parseTCPGuardStringValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if args, n, ok := parseTCPGuardCallArgs(raw, "env"); ok {
		return formatTCPGuardCallTemplate("env", args, n)
	}
	if args, n, ok := parseTCPGuardCallArgs(raw, "context"); ok {
		return formatTCPGuardCallTemplate("context", args, n)
	}
	if args, n, ok := parseTCPGuardCallArgs(raw, "session"); ok {
		return formatTCPGuardCallTemplate("session", args, n)
	}
	return trimTCPGuardQuote(raw)
}

func formatTCPGuardCallTemplate(name string, args [2]string, n int) string {
	if n <= 0 {
		return ""
	}
	if n == 1 {
		return "{{" + name + "(" + strconv.Quote(args[0]) + ")}}"
	}
	return "{{" + name + "(" + strconv.Quote(args[0]) + ", " + strconv.Quote(args[1]) + ")}}"
}

func parseTCPGuardList(line string) []string {
	start := strings.IndexByte(line, '[')
	end := strings.LastIndexByte(line, ']')
	if start < 0 || end < start {
		_, rest, ok := cutTCPGuardField(line)
		if !ok {
			return nil
		}
		value, _, ok := cutTCPGuardField(rest)
		if ok {
			return []string{trimTCPGuardQuote(value)}
		}
		return nil
	}
	raw := line[start+1 : end]
	out := make([]string, 0, countTCPGuardListItems(raw))
	for len(raw) > 0 {
		part := raw
		if idx := strings.IndexByte(raw, ','); idx >= 0 {
			part = raw[:idx]
			raw = raw[idx+1:]
		} else {
			raw = ""
		}
		part = trimTCPGuardQuote(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func countTCPGuardListItems(raw string) int {
	if raw == "" {
		return 0
	}
	n := 1
	for i := 0; i < len(raw); i++ {
		if raw[i] == ',' {
			n++
		}
	}
	return n
}

func lastTCPGuardByteField(line []byte) []byte {
	line = trimTCPGuardBytes(line)
	if len(line) == 0 {
		return nil
	}
	end := len(line)
	for end > 0 && isTCPGuardSpace(line[end-1]) {
		end--
	}
	start := end
	for start > 0 && !isTCPGuardSpace(line[start-1]) {
		start--
	}
	return line[start:end]
}

func indexTCPGuardWord(fields []string, word string) int {
	for i, field := range fields {
		if field == word {
			return i
		}
	}
	return -1
}

func findTCPGuardIncludes(data []byte) []string {
	var out []string
	for len(data) > 0 {
		line := data
		if idx := bytesIndexByte(data, '\n'); idx >= 0 {
			line = data[:idx]
			data = data[idx+1:]
		} else {
			data = nil
		}
		line = trimTCPGuardBytes(line)
		if bytesHasPrefix(line, "include ") {
			include := lastTCPGuardByteField(line)
			if len(include) > 0 {
				out = append(out, trimTCPGuardQuote(string(include)))
			}
		}
	}
	return out
}

func mergeTCPGuardBundle(dst *tcpguard.Bundle, src tcpguard.Bundle) {
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if src.Version != "" {
		dst.Version = src.Version
	}
	if src.Authz.File != "" || src.Authz.Strict || src.Authz.Timeout > 0 || src.Authz.ErrorPolicy != "" {
		dst.Authz = src.Authz
	}
	if src.Mode != "" {
		dst.Mode = src.Mode
	}
	dst.Rules = append(dst.Rules, src.Rules...)
	dst.Actions = append(dst.Actions, src.Actions...)
	dst.DataSources = append(dst.DataSources, src.DataSources...)
	dst.Lookups = append(dst.Lookups, src.Lookups...)
	dst.DerivedEvents = append(dst.DerivedEvents, src.DerivedEvents...)
	dst.Detectors = append(dst.Detectors, src.Detectors...)
	dst.Enrichers = append(dst.Enrichers, src.Enrichers...)
	dst.IntelFeeds = append(dst.IntelFeeds, src.IntelFeeds...)
	dst.Baselines = append(dst.Baselines, src.Baselines...)
	dst.ThreatModels = append(dst.ThreatModels, src.ThreatModels...)
}

func normalizeTCPGuardBundlePaths(bundle *tcpguard.Bundle, base string) {
	for i := range bundle.IntelFeeds {
		if bundle.IntelFeeds[i].Type == "file" {
			bundle.IntelFeeds[i].Path = resolveTCPGuardPath(base, bundle.IntelFeeds[i].Path)
		}
	}
	for i := range bundle.Enrichers {
		bundle.Enrichers[i].Source = resolveTCPGuardSource(base, bundle.Enrichers[i].Source)
	}
	for i := range bundle.DataSources {
		if bundle.DataSources[i].Type == "csv" || bundle.DataSources[i].Type == "json" {
			bundle.DataSources[i].Path = resolveTCPGuardPath(base, bundle.DataSources[i].Path)
		}
	}
	bundle.Authz.File = resolveTCPGuardPath(base, bundle.Authz.File)
}

func resolveTCPGuardSource(base, source string) string {
	fields := strings.Fields(source)
	if len(fields) == 2 && fields[0] == "file" {
		return "file " + resolveTCPGuardPath(base, trimTCPGuardQuote(fields[1]))
	}
	return source
}

func resolveTCPGuardPath(base, path string) string {
	path = trimTCPGuardQuote(path)
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "{{") || hasTCPGuardPrefix(path, "env(") {
		return path
	}
	return filepath.Join(base, path)
}

func firstTCPGuardNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseTCPGuardScalar(raw string) any {
	raw = trimTCPGuardQuote(raw)
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}
	return raw
}

func parseTCPGuardValue(raw string) any {
	raw = strings.TrimSpace(raw)
	if path, ok := parseTCPGuardPlaceholder(raw); ok {
		return tcpguard.Placeholder(path)
	}
	if args, n, ok := parseTCPGuardCallArgs(raw, "env"); ok {
		return tcpguard.EnvRef(joinTCPGuardRefArgs(args, n))
	}
	if args, n, ok := parseTCPGuardCallArgs(raw, "context"); ok {
		return tcpguard.ContextRef(joinTCPGuardRefArgs(args, n))
	}
	if args, n, ok := parseTCPGuardCallArgs(raw, "session"); ok {
		return tcpguard.SessionRef(joinTCPGuardRefArgs(args, n))
	}
	return parseTCPGuardScalar(raw)
}

func joinTCPGuardRefArgs(args [2]string, n int) string {
	if n <= 0 {
		return ""
	}
	if n == 1 {
		return args[0]
	}
	return args[0] + bclRefArgSep + args[1]
}

func parseTCPGuardPlaceholder(raw string) (string, bool) {
	raw = trimTCPGuardQuote(raw)
	if hasTCPGuardPrefix(raw, "{{") && strings.HasSuffix(raw, "}}") {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{{"), "}}")), true
	}
	return "", false
}

func parseTCPGuardCall(raw, name string) (string, bool) {
	args, n, ok := parseTCPGuardCallArgs(raw, name)
	if !ok || n == 0 {
		return "", false
	}
	return args[0], true
}

func parseTCPGuardCallArgs(raw, name string) ([2]string, int, bool) {
	var out [2]string
	raw = strings.TrimSpace(raw)
	if len(raw) <= len(name)+1 || raw[len(name)] != '(' || !hasTCPGuardPrefix(raw, name) || !strings.HasSuffix(raw, ")") {
		return out, 0, false
	}
	value := strings.TrimSpace(raw[len(name)+1 : len(raw)-1])
	if value == "" {
		return out, 0, false
	}
	n, ok := splitTCPGuardArgs(value, &out)
	if !ok || n < 1 || n > 2 || strings.TrimSpace(out[0]) == "" {
		return out, 0, false
	}
	return out, n, true
}

func splitTCPGuardArgs(raw string, out *[2]string) (int, bool) {
	n := 0
	start := 0
	quote := rune(0)
	depth := 0
	escaped := false
	for i, r := range raw {
		switch {
		case quote != 0:
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '(':
			depth++
		case r == ')':
			if depth > 0 {
				depth--
			}
		case r == ',' && depth == 0:
			if n == len(out) {
				return 0, false
			}
			out[n] = cleanTCPGuardArg(raw[start:i])
			n++
			start = i + len(",")
		}
	}
	if quote != 0 {
		return 0, false
	}
	if n == len(out) {
		return 0, false
	}
	last := strings.TrimSpace(raw[start:])
	if last != "" {
		out[n] = cleanTCPGuardArg(last)
		n++
	}
	return n, true
}

func cleanTCPGuardArg(arg string) string {
	arg = strings.TrimSpace(arg)
	if strings.IndexByte(arg, '\\') < 0 {
		return trimTCPGuardQuote(arg)
	}
	return trimTCPGuardQuote(strings.ReplaceAll(arg, `\"`, `"`))
}
