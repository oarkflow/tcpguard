package bcl

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oarkflow/condition/tcpguard"
)

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
	for _, include := range findTCPGuardIncludes(string(data)) {
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
		switch {
		case strings.HasPrefix(line, "guard "):
			if err := p.parseGuard(); err != nil {
				return p.out, err
			}
		case strings.HasPrefix(line, "pack "):
			if err := p.parsePack(); err != nil {
				return p.out, err
			}
		case strings.HasPrefix(line, "rule "):
			rule, err := p.parseRule()
			if err != nil {
				return p.out, err
			}
			p.out.Rules = append(p.out.Rules, rule)
		case strings.HasPrefix(line, "datasource "):
			p.out.DataSources = append(p.out.DataSources, p.parseDataSource())
		case strings.HasPrefix(line, "lookup "):
			p.out.Lookups = append(p.out.Lookups, p.parseLookup())
		case strings.HasPrefix(line, "action "):
			action, err := p.parseAction()
			if err != nil {
				return p.out, err
			}
			p.out.Actions = append(p.out.Actions, action)
		case strings.HasPrefix(line, "trigger "):
			trigger, err := p.parseTrigger()
			if err != nil {
				return p.out, err
			}
			p.out.DerivedEvents = append(p.out.DerivedEvents, trigger)
		case strings.HasPrefix(line, "detector "):
			p.out.Detectors = append(p.out.Detectors, p.parseDetector())
		case strings.HasPrefix(line, "enricher "):
			p.out.Enrichers = append(p.out.Enrichers, p.parseEnricher())
		case strings.HasPrefix(line, "intel "):
			p.out.IntelFeeds = append(p.out.IntelFeeds, p.parseIntel())
		case strings.HasPrefix(line, "baseline "):
			p.out.Baselines = append(p.out.Baselines, p.parseBaseline())
		case strings.HasPrefix(line, "threat_model "):
			p.out.ThreatModels = append(p.out.ThreatModels, p.parseThreatModel())
		case strings.HasPrefix(line, "policy_safety"):
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "version":
				p.out.Version = trimTCPGuardQuote(fields[1])
			case "mode":
				p.out.Mode = tcpguard.Mode(fields[1])
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "mode":
				p.out.Mode = tcpguard.Mode(fields[1])
			case "version":
				p.out.Version = trimTCPGuardQuote(fields[1])
			case "timezone":
				p.out.Timezone = trimTCPGuardQuote(fields[1])
			}
		}
		p.i++
	}
	return nil
}

func (p *tcpGuardParser) parseRule() (tcpguard.Rule, error) {
	rule := tcpguard.Rule{ID: quotedTCPGuardName(p.line()), Status: tcpguard.RuleActive, Risk: tcpguard.RiskSpec{Max: 100}, Actions: map[tcpguard.Severity][]tcpguard.ActionRef{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return rule, nil
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "name":
				rule.Name = trimTCPGuardQuote(strings.Join(fields[1:], " "))
			case "status":
				rule.Status = tcpguard.RuleStatus(fields[1])
			case "priority":
				rule.Priority, _ = strconv.Atoi(fields[1])
			case "version":
				rule.Version, _ = strconv.Atoi(fields[1])
			case "owner":
				rule.Owner = trimTCPGuardQuote(fields[1])
			}
		}
		switch {
		case strings.HasPrefix(line, "scope"):
			rule.Scope = p.parseScope()
		case strings.HasPrefix(line, "trigger"):
			rule.Triggers, rule.Sequence = p.parseRuleTrigger()
		case strings.HasPrefix(line, "when"):
			rule.Condition = p.parseConditionBlock()
		case strings.HasPrefix(line, "risk"):
			rule.Risk = p.parseRisk()
		case strings.HasPrefix(line, "severity"):
			rule.Severity = p.parseSeverity()
		case strings.HasPrefix(line, "actions"):
			rule.Actions = p.parseActions()
		case strings.HasPrefix(line, "cooldown"):
			rule.Cooldown = p.parseCooldown()
		case strings.HasPrefix(line, "approval"):
			rule.Approval = p.parseApproval()
		default:
			p.i++
		}
	}
	return rule, nil
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
		switch {
		case strings.HasPrefix(line, "tenants"):
			scope.Tenants = parseTCPGuardList(line)
		case strings.HasPrefix(line, "roles"):
			scope.Roles = parseTCPGuardList(line)
		case strings.HasPrefix(line, "methods"):
			scope.Methods = parseTCPGuardList(line)
		case strings.HasPrefix(line, "paths"):
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
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "on" {
			triggers = append(triggers, fields[1])
		}
		if len(fields) >= 3 && fields[0] == "sequence" && fields[1] == "within" {
			d, _ := time.ParseDuration(fields[2])
			sequence = &tcpguard.SequenceTrigger{Within: d}
			p.i++
			for p.i < len(p.lines) {
				inner := p.line()
				if inner == "}" {
					p.i++
					break
				}
				parts := strings.Fields(inner)
				if len(parts) > 0 {
					step := tcpguard.SequenceStep{Event: parts[0]}
					if idx := indexTCPGuardWord(parts, "count"); idx >= 0 && len(parts) > idx+2 {
						step.Count, _ = strconv.Atoi(parts[idx+2])
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
	return flattenTCPGuardCondition(p.collectBlock())
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "base":
				risk.Base, _ = strconv.ParseFloat(fields[1], 64)
			case "max":
				risk.Max, _ = strconv.ParseFloat(fields[1], 64)
			case "decay":
				risk.Decay, _ = time.ParseDuration(fields[1])
			case "profile":
				risk.Profile = parseTCPGuardList(line)
			case "add":
				value, _ := strconv.ParseFloat(fields[1], 64)
				cond := ""
				if idx := indexTCPGuardWord(fields, "when"); idx >= 0 {
					cond = strings.Join(fields[idx+1:], " ")
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
		fields := strings.Fields(line)
		if idx := indexTCPGuardWord(fields, "when"); idx >= 0 {
			out = append(out, tcpguard.SeverityRule{Severity: tcpguard.Severity(fields[0]), Condition: strings.Join(fields[idx+1:], " ")})
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
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.HasSuffix(line, "{") {
			severity := tcpguard.Severity(fields[0])
			p.i++
			for p.i < len(p.lines) {
				inner := p.line()
				if inner == "}" {
					p.i++
					break
				}
				parts := strings.Fields(inner)
				if len(parts) >= 2 && parts[0] == "run" {
					out[severity] = append(out[severity], tcpguard.ActionRef{ID: trimTCPGuardQuote(parts[1]), Args: parts[2:]})
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if fields[0] == "key" {
				c.Key = fields[1]
			}
			if fields[0] == "duration" {
				c.Duration, _ = time.ParseDuration(fields[1])
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
		if strings.HasPrefix(line, "required") {
			a.Required = strings.Contains(line, "true")
		}
		if strings.HasPrefix(line, "approvers") {
			a.Approvers = parseTCPGuardList(line)
		}
		p.i++
	}
	return a
}

func (p *tcpGuardParser) parseAction() (tcpguard.ActionDefinition, error) {
	action := tcpguard.ActionDefinition{
		ID:      quotedTCPGuardName(p.line()),
		Method:  "POST",
		Headers: map[string]string{},
		Request: tcpguard.ActionRequest{Method: "POST", Headers: map[string]string{}, Body: map[string]any{}, Include: map[string]string{}, Fields: map[string]any{}},
	}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return action, nil
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "type":
				action.Type = fields[1]
			case "endpoint":
				action.Endpoint = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "method":
				action.Method = fields[1]
			case "provider":
				action.Provider = fields[1]
			case "subject":
				action.Subject = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "timeout":
				action.Timeout, _ = time.ParseDuration(fields[1])
			}
		}
		switch {
		case strings.HasPrefix(line, "headers"):
			action.Request.Headers = p.parseStringMapBlock()
			action.Headers = action.Request.Headers
			continue
		case strings.HasPrefix(line, "body"):
			template, body, include, fields := p.parseBodyBlock()
			action.Request.BodyTemplate = template
			action.BodyTemplate = template
			action.Request.Body = body
			action.Request.Include = include
			action.Request.Fields = fields
			continue
		case strings.HasPrefix(line, "payload"):
			_, body, include, fields := p.parseBodyBlock()
			action.Request.Body = body
			action.Request.Include = include
			action.Request.Fields = fields
			continue
		case strings.HasPrefix(line, "request"):
			req := p.parseRequestBlock()
			action.Request = req
			action.Endpoint = firstTCPGuardNonEmpty(action.Endpoint, req.Endpoint)
			action.Method = firstTCPGuardNonEmpty(action.Method, req.Method)
			action.Headers = req.Headers
			action.BodyTemplate = req.BodyTemplate
			continue
		case strings.HasPrefix(line, "retry"):
			action.Retry = p.parseRetryBlock()
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "attempts":
				retry.Attempts, _ = strconv.Atoi(fields[1])
			case "backoff":
				retry.Backoff = fields[1]
			}
		}
		p.i++
	}
	return retry
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "source":
				trigger.Source = fields[1]
			case "emit":
				trigger.Emit = trimTCPGuardQuote(fields[1])
			}
		}
		if strings.HasPrefix(line, "when") {
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "type":
				def.Type = fields[1]
			case "prefix":
				def.Prefix = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "path":
				def.Path = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "key":
				def.Key = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "url":
				def.URL = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "method":
				def.Method = fields[1]
			case "driver":
				def.Driver = fields[1]
			case "dsn":
				def.DSN = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "timeout":
				def.Timeout, _ = time.ParseDuration(fields[1])
			}
		}
		if strings.HasPrefix(line, "headers") {
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
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "source":
				def.Source = trimTCPGuardQuote(fields[1])
			case "mode":
				def.Mode = fields[1]
			case "key":
				def.Key = strings.Join(fields[1:], " ")
			case "query":
				def.Query = parseTCPGuardStringValue(strings.Join(fields[1:], " "))
			case "timeout":
				def.Timeout, _ = time.ParseDuration(fields[1])
			}
		}
		switch {
		case strings.HasPrefix(line, "params"):
			def.Params = p.parseLookupParams()
			continue
		case strings.HasPrefix(line, "output"):
			def.Outputs = p.parseLookupOutput()
			continue
		case strings.HasPrefix(line, "fallback"):
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
			case "field":
				if len(fields) >= 3 {
					def.Outputs[fields[1]] = parseTCPGuardValue(strings.Join(fields[2:], " "))
				}
			}
		}
		switch {
		case strings.HasPrefix(line, "finding "):
			def.Findings = append(def.Findings, p.parseDetectorFinding())
			continue
		case strings.HasPrefix(line, "output"):
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
		def.Condition = flattenTCPGuardCondition(p.collectBlock())
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
		if strings.HasPrefix(line, "when") {
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
		if strings.HasPrefix(line, "fields") {
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
				if strings.HasPrefix(inner, "findings") {
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

func (p *tcpGuardParser) collectBlock() []string {
	depth := 1
	var out []string
	for p.i < len(p.lines) {
		line := p.line()
		open := strings.Count(line, "{")
		close := strings.Count(line, "}")
		if close > 0 && depth-close <= 0 {
			p.i++
			return out
		}
		switch line {
		case "all {", "any {", "not {":
			out = append(out, strings.TrimSuffix(line, " {"))
		case "}":
			out = append(out, line)
		default:
			out = append(out, strings.TrimSuffix(line, "{"))
		}
		depth += open - close
		p.i++
	}
	return out
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
	body := map[string]any{}
	include := map[string]string{}
	fields := map[string]any{}
	var template string
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return template, body, include, fields
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			switch parts[0] {
			case "template":
				template = trimTCPGuardQuote(strings.Join(parts[1:], " "))
			case "include":
				path := parts[1]
				alias := strings.ReplaceAll(path, ".", "_")
				if len(parts) >= 4 && parts[2] == "as" {
					alias = trimTCPGuardQuote(parts[3])
				}
				include[alias] = path
			case "field":
				if len(parts) >= 3 {
					fields[parts[1]] = parseTCPGuardValue(strings.Join(parts[2:], " "))
				}
			default:
				body[parts[0]] = parseTCPGuardValue(strings.Join(parts[1:], " "))
			}
		}
		p.i++
	}
	return template, body, include, fields
}

func (p *tcpGuardParser) parseRequestBlock() tcpguard.ActionRequest {
	req := tcpguard.ActionRequest{Method: "POST", Headers: map[string]string{}, Body: map[string]any{}, Include: map[string]string{}, Fields: map[string]any{}}
	p.i++
	for p.i < len(p.lines) {
		line := p.line()
		if line == "}" {
			p.i++
			return req
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			switch parts[0] {
			case "endpoint":
				req.Endpoint = parseTCPGuardStringValue(strings.Join(parts[1:], " "))
			case "method":
				req.Method = parts[1]
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
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func flattenTCPGuardCondition(lines []string) string {
	expr, _ := parseTCPGuardConditionLines(lines, 0, "all")
	return expr
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

func parseTCPGuardConditionLines(lines []string, i int, mode string) (string, int) {
	var terms []string
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		line = strings.TrimSuffix(line, "{")
		line = strings.TrimSpace(line)
		switch line {
		case "}":
			return joinTCPGuardTerms(mode, terms), i + 1
		case "all", "any", "not":
			expr, next := parseTCPGuardConditionLines(lines, i+1, line)
			if expr != "" {
				terms = append(terms, expr)
			}
			i = next
			continue
		default:
			line = strings.TrimSuffix(line, "}")
			if strings.TrimSpace(line) != "" {
				terms = append(terms, normalizeTCPGuardCondition(line))
			}
		}
		i++
	}
	return joinTCPGuardTerms(mode, terms), i
}

func joinTCPGuardTerms(mode string, terms []string) string {
	if len(terms) == 0 {
		return ""
	}
	if mode == "not" {
		return "not (" + strings.Join(terms, " and ") + ")"
	}
	sep := " and "
	if mode == "any" {
		sep = " or "
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return "(" + strings.Join(terms, sep) + ")"
}

func normalizeTCPGuardWildcardMatch(s string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) == 3 && fields[1] == "matches" {
		return "wildcard_match(" + fields[0] + ", " + fields[2] + ")", true
	}
	return "", false
}

func quotedTCPGuardName(line string) string {
	start := strings.IndexByte(line, '"')
	if start < 0 {
		fields := strings.Fields(line)
		if len(fields) > 1 {
			return fields[1]
		}
		return ""
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
	if strings.HasPrefix(line, `"`) {
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		key := line[1 : 1+end]
		value := strings.TrimSpace(line[1+end+1:])
		return key, parseTCPGuardStringValue(value), value != ""
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parseTCPGuardStringValue(strings.Join(parts[1:], " ")), true
}

func parseTCPGuardStringValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if name, ok := parseTCPGuardCall(raw, "env"); ok {
		return "{{env(" + strconv.Quote(name) + ")}}"
	}
	if path, ok := parseTCPGuardCall(raw, "context"); ok {
		return "{{context(" + strconv.Quote(path) + ")}}"
	}
	if path, ok := parseTCPGuardCall(raw, "session"); ok {
		return "{{session(" + strconv.Quote(path) + ")}}"
	}
	return trimTCPGuardQuote(raw)
}

func parseTCPGuardList(line string) []string {
	start := strings.IndexByte(line, '[')
	end := strings.LastIndexByte(line, ']')
	if start < 0 || end < start {
		fields := strings.Fields(line)
		if len(fields) > 1 {
			return []string{trimTCPGuardQuote(fields[1])}
		}
		return nil
	}
	raw := line[start+1 : end]
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = trimTCPGuardQuote(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func indexTCPGuardWord(fields []string, word string) int {
	for i, field := range fields {
		if field == word {
			return i
		}
	}
	return -1
}

func findTCPGuardIncludes(data string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "include ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				out = append(out, trimTCPGuardQuote(fields[len(fields)-1]))
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
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "{{") || strings.HasPrefix(path, "env(") {
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
	if name, ok := parseTCPGuardCall(raw, "env"); ok {
		return tcpguard.EnvRef(name)
	}
	if path, ok := parseTCPGuardCall(raw, "context"); ok {
		return tcpguard.ContextRef(path)
	}
	if path, ok := parseTCPGuardCall(raw, "session"); ok {
		return tcpguard.SessionRef(path)
	}
	return parseTCPGuardScalar(raw)
}

func parseTCPGuardPlaceholder(raw string) (string, bool) {
	raw = trimTCPGuardQuote(raw)
	if strings.HasPrefix(raw, "{{") && strings.HasSuffix(raw, "}}") {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{{"), "}}")), true
	}
	return "", false
}

func parseTCPGuardCall(raw, name string) (string, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, `\"`, `"`)
	if !strings.HasPrefix(raw, name+"(") || !strings.HasSuffix(raw, ")") {
		return "", false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(raw, name+"("), ")")
	return trimTCPGuardQuote(value), true
}
