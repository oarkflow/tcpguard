package tcpguard

import (
	"fmt"
	"strings"
	"unicode"
)

func buildNoMatchExplanation(sec *Context) string {
	return fmt.Sprintf("Allowed %s because no TCPGuard rule matched this request.", requestSubject(sec))
}

func buildStateBlockExplanation(sec *Context, finding Finding) string {
	reason := strings.TrimSpace(finding.Message)
	if reason == "" {
		reason = strings.TrimSpace(finding.ID)
	}
	if reason == "" {
		reason = "TCPGuard state marked this request as blocked"
	}
	return fmt.Sprintf("Blocked %s because %s.", requestSubject(sec), lowercaseFirst(reason))
}

func buildDecisionExplanation(sec *Context, event Event, decision Decision, results []RuleResult) string {
	if len(results) == 0 {
		return buildNoMatchExplanation(sec)
	}
	top := highestRiskResult(results)
	ruleName := ruleDisplayName(top.Rule)
	verb := decisionEffectVerb(decision)
	subject := requestSubject(sec)
	reasons := explanationReasons(sec, top)
	summary := fmt.Sprintf("%s %s because rule %q matched", verb, subject, ruleName)
	if len(reasons) > 0 {
		summary += ": " + strings.Join(reasons, "; ")
	}
	parts := []string{summary + "."}
	if len(results) > 1 {
		parts = append(parts, fmt.Sprintf("%d total rules matched for event %q.", len(results), event.Type))
	}
	return strings.Join(parts, " ")
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
	if sec == nil {
		return "the request"
	}
	method := strings.TrimSpace(sec.Request.Method)
	path := strings.TrimSpace(sec.Request.Path)
	var subject string
	switch {
	case method != "" && path != "":
		subject = method + " " + path
	case path != "":
		subject = path
	default:
		subject = "the request"
	}
	var attrs []string
	if sec.Network.IP != "" {
		attrs = append(attrs, "IP "+sec.Network.IP)
	}
	if sec.Identity.ID != "" {
		user := "user " + sec.Identity.ID
		if sec.Identity.Role != "" {
			user += " (" + sec.Identity.Role + ")"
		}
		attrs = append(attrs, user)
	}
	tenantID := firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant)
	if tenantID != "" {
		attrs = append(attrs, "tenant "+tenantID)
	}
	if len(attrs) > 0 {
		subject += " from " + strings.Join(attrs, ", ")
	}
	return subject
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
