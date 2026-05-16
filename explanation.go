package tcpguard

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

func buildNoMatchExplanation(sec *Context) string {
	var b strings.Builder
	b.Grow(requestSubjectLen(sec) + len("Allowed  because no TCPGuard rule matched this request."))
	b.WriteString("Allowed ")
	appendRequestSubject(&b, sec)
	b.WriteString(" because no TCPGuard rule matched this request.")
	return b.String()
}

func buildStateBlockExplanation(sec *Context, finding Finding) string {
	reason := strings.TrimSpace(finding.Message)
	if reason == "" {
		reason = strings.TrimSpace(finding.ID)
	}
	if reason == "" {
		reason = "TCPGuard state marked this request as blocked"
	}
	return "Blocked " + requestSubject(sec) + " because " + lowercaseFirst(reason) + "."
}

func buildDecisionExplanation(sec *Context, event Event, decision Decision, results []RuleResult) string {
	if len(results) == 0 {
		return buildNoMatchExplanation(sec)
	}
	top := highestRiskResult(results)
	ruleName := ruleDisplayName(top.Rule)
	verb := decisionEffectVerb(decision)
	var b strings.Builder
	b.Grow(requestSubjectLen(sec) + len(verb) + len(ruleName) + 96)
	b.WriteString(verb)
	b.WriteByte(' ')
	appendRequestSubject(&b, sec)
	b.WriteString(" because rule ")
	b.WriteByte('"')
	b.WriteString(ruleName)
	b.WriteString("\" matched")
	if top.Rule != nil && top.Rule.Condition == "" && len(top.Findings) == 0 {
		b.WriteString(": the request matched the rule conditions")
	} else if reasons := explanationReasons(sec, top); len(reasons) > 0 {
		b.WriteString(": ")
		for i, reason := range reasons {
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(reason)
		}
	}
	b.WriteByte('.')
	if len(results) > 1 {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(len(results)))
		b.WriteString(" total rules matched for event ")
		b.WriteByte('"')
		b.WriteString(event.Type)
		b.WriteString("\".")
	}
	return b.String()
}

func buildLookupFailureExplanation(sec *Context, failure LookupFailure, effect DecisionEffect) string {
	reason := strings.TrimSpace(failure.Lookup.Fallback.Reason)
	if reason == "" && failure.Err != nil {
		reason = failure.Err.Error()
	}
	if reason == "" {
		reason = "a required datasource lookup failed"
	}
	action := "Challenged"
	if effect == DecisionBlock {
		action = "Blocked"
	}
	lookupID := firstNonEmpty(failure.Lookup.ID, failure.Lookup.Source, "unknown lookup")
	return fmt.Sprintf("%s %s because lookup %q could not be trusted: %s.", action, requestSubject(sec), lookupID, lowercaseFirst(reason))
}

func buildApprovalChallengeExplanation(sec *Context, approvals []ApprovalRecord) string {
	for _, approval := range approvals {
		if approval.Status == ApprovalRejected {
			reason := strings.TrimSpace(approval.Reason)
			if reason == "" {
				reason = "an approver rejected the request"
			}
			return fmt.Sprintf("Blocked %s because approval for rule %q was rejected: %s.", requestSubject(sec), approval.RuleID, lowercaseFirst(reason))
		}
	}
	if len(approvals) == 0 {
		return fmt.Sprintf("Challenged %s because this decision requires approval.", requestSubject(sec))
	}
	var rules []string
	for _, approval := range approvals {
		if approval.RuleID != "" {
			rules = append(rules, approval.RuleID)
		}
	}
	if len(rules) == 0 {
		return fmt.Sprintf("Challenged %s because this decision requires approval.", requestSubject(sec))
	}
	return fmt.Sprintf("Challenged %s because rule approval is required before enforcement. Pending approval for: %s.", requestSubject(sec), strings.Join(uniqueStrings(rules), ", "))
}

func highestRiskResult(results []RuleResult) RuleResult {
	top := results[0]
	for _, result := range results[1:] {
		if result.Risk.Score > top.Risk.Score {
			top = result
		}
	}
	return top
}

func ruleDisplayName(rule *Rule) string {
	if rule == nil {
		return "unknown rule"
	}
	if rule.Name != "" {
		return fmt.Sprintf("%s (%s)", rule.Name, rule.ID)
	}
	return rule.ID
}

func decisionEffectVerb(decision Decision) string {
	switch decision.Effect {
	case DecisionBlock:
		return "Blocked"
	case DecisionChallenge:
		return "Challenged"
	case DecisionThrottle:
		return "Throttled"
	case DecisionRevoke:
		return "Revoked access for"
	case DecisionMonitor:
		if decision.Allowed {
			return "Allowed but monitored"
		}
		return "Monitored"
	default:
		if decision.Allowed {
			return "Allowed"
		}
		return "Stopped"
	}
}

func requestSubject(sec *Context) string {
	var b strings.Builder
	b.Grow(requestSubjectLen(sec))
	appendRequestSubject(&b, sec)
	return b.String()
}

func requestSubjectLen(sec *Context) int {
	if sec == nil {
		return len("the request")
	}
	method := strings.TrimSpace(sec.Request.Method)
	path := strings.TrimSpace(sec.Request.Path)
	n := len(sec.Network.IP) + len(sec.Identity.ID) + len(sec.Identity.Role) + len(sec.Tenant.ID) + len(sec.Identity.Tenant) + 40
	switch {
	case method != "" && path != "":
		n += len(method) + 1 + len(path)
	case path != "":
		n += len(path)
	default:
		n += len("the request")
	}
	return n
}

func appendRequestSubject(b *strings.Builder, sec *Context) {
	if sec == nil {
		b.WriteString("the request")
		return
	}
	method := strings.TrimSpace(sec.Request.Method)
	path := strings.TrimSpace(sec.Request.Path)
	switch {
	case method != "" && path != "":
		b.WriteString(method)
		b.WriteByte(' ')
		b.WriteString(path)
	case path != "":
		b.WriteString(path)
	default:
		b.WriteString("the request")
	}
	wroteAttr := false
	if sec.Network.IP != "" {
		b.WriteString(" from IP ")
		b.WriteString(sec.Network.IP)
		wroteAttr = true
	}
	if sec.Identity.ID != "" {
		if wroteAttr {
			b.WriteString(", ")
		} else {
			b.WriteString(" from ")
			wroteAttr = true
		}
		b.WriteString("user ")
		b.WriteString(sec.Identity.ID)
		if sec.Identity.Role != "" {
			b.WriteString(" (")
			b.WriteString(sec.Identity.Role)
			b.WriteByte(')')
		}
	}
	tenantID := firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant)
	if tenantID != "" {
		if wroteAttr {
			b.WriteString(", ")
		} else {
			b.WriteString(" from ")
		}
		b.WriteString("tenant ")
		b.WriteString(tenantID)
	}
}

func explanationReasons(sec *Context, result RuleResult) []string {
	seen := map[string]bool{}
	var reasons []string
	if result.Rule != nil {
		for _, reason := range humanConditionReasons(sec, result.Rule.Condition) {
			if reason != "" && !seen[reason] {
				seen[reason] = true
				reasons = append(reasons, reason)
			}
		}
	}
	for _, finding := range result.Findings {
		reason := strings.TrimSpace(finding.Message)
		if reason == "" {
			reason = strings.TrimSpace(finding.ID)
		}
		if reason != "" && !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "the request matched the rule conditions")
	}
	if len(reasons) > 3 {
		return reasons[:3]
	}
	return reasons
}

func humanConditionReasons(sec *Context, condition string) []string {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return nil
	}
	var out []string
	checks := []struct {
		token  string
		reason string
	}{
		{"network.ip.blacklisted", "the IP address is listed in threat intelligence"},
		{"network.country", "the request came from a country restricted by policy"},
		{"network.country_code", "the request came from a country restricted by policy"},
		{"business.outside_hours", "the action happened outside business hours"},
		{"session.device.new", "the session is using a new device"},
		{"security.signature.valid", "the request signature failed validation"},
		{"security.nonce.reused", "the request nonce was reused"},
		{"security.body_hash.valid", "the request body hash failed validation"},
		{"rate.ip.requests", "the IP address exceeded a rate limit"},
		{"rate.user.requests", "the user exceeded a rate limit"},
		{"rate.tenant.requests", "the tenant exceeded a rate limit"},
		{"store.exists", "an external lookup matched a blocked or risky record"},
		{"store.field", "an external lookup returned a risky account or tenant field"},
		{"store.value", "an external lookup returned a risky value"},
	}
	for _, check := range checks {
		if strings.Contains(condition, check.token) {
			out = append(out, check.reason)
		}
	}
	if len(out) > 0 {
		return out
	}
	return []string{humanizeCondition(condition)}
}

func humanizeCondition(condition string) string {
	condition = strings.TrimSpace(condition)
	replacements := []struct {
		old string
		new string
	}{
		{" greater_or_equal ", " is at least "},
		{" greater_than ", " is greater than "},
		{" less_or_equal ", " is at most "},
		{" less_than ", " is less than "},
		{" not_equals ", " is not "},
		{" equals ", " is "},
		{" == ", " is "},
		{" != ", " is not "},
		{" >= ", " is at least "},
		{" <= ", " is at most "},
		{" > ", " is greater than "},
		{" < ", " is less than "},
		{"&&", " and "},
		{"||", " or "},
	}
	for _, replacement := range replacements {
		condition = strings.ReplaceAll(condition, replacement.old, replacement.new)
	}
	condition = strings.ReplaceAll(condition, "_", " ")
	return strings.Join(strings.Fields(condition), " ")
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func lowercaseFirst(value string) string {
	if value == "" {
		return value
	}
	runes := []rune(value)
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}
