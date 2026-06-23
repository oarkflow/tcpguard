package tcpguard

import (
	"sort"
	"time"
)

// DecisionLogEntry builds an operator-facing structured log entry for a TCPGuard
// decision. Unlike PublicDecisionBody, this is intended for trusted application
// logs/SIEM pipelines. Production keeps the entry detailed but suppresses raw
// sensitive values. Development/test may include safe diagnostic values when the
// supplied ResponseMessagePolicy allows values.
func DecisionLogEntry(sec *Context, decision Decision, policy ResponseMessagePolicy) map[string]any {
	policy = normalizeResponsePolicy(policy)
	entry := map[string]any{
		"component":      "tcpguard",
		"event":          "tcpguard.decision",
		"environment":    policy.Environment,
		"effect":         decision.Effect,
		"allowed":        decision.Allowed,
		"severity":       decision.Severity,
		"risk_score":     decision.Risk.Score,
		"confidence":     decision.Risk.Confidence,
		"message":        PublicDecisionMessage(sec, decision, policy),
		"explanation":    sanitizePublicText(decision.Explanation, policy),
		"policy_version": decision.PolicyVersion,
		"config_hash":    decision.ConfigHash,
		"matched_rules":  sanitizeStringSlice(decision.MatchedRules, forceRuleIDLogging(policy)),
		"findings":       decisionLogFindings(decision.Findings, policy),
		"evidence":       decisionLogEvidence(decision.Evidence, policy),
		"actions":        decisionLogActions(decision.Actions, policy),
		"incidents":      len(decision.Incidents),
		"approvals":      approvalIDs(decision.Approvals),
		"at":             time.Now().UTC().Format(time.RFC3339Nano),
	}
	if sec != nil {
		entry["request"] = decisionLogRequest(sec, policy)
		entry["network"] = decisionLogNetwork(sec, policy)
		entry["identity"] = decisionLogIdentity(sec, policy)
		entry["tenant"] = decisionLogTenant(sec, policy)
		entry["business"] = decisionLogBusiness(sec, policy)
	}
	if decision.Trace != nil {
		entry["trace"] = decision.Trace
	}
	if decision.AuditEnvelope != nil {
		entry["audit_envelope"] = map[string]any{"id": decision.AuditEnvelope.ID, "sequence": decision.AuditEnvelope.Sequence, "chain_hash": decision.AuditEnvelope.ChainHash, "payload_hash": decision.AuditEnvelope.PayloadHash, "previous_hash": decision.AuditEnvelope.PreviousHash}
	}
	return entry
}

func forceRuleIDLogging(policy ResponseMessagePolicy) ResponseMessagePolicy {
	policy.IncludeRuleIDs = true
	return policy
}

func decisionLogRequest(sec *Context, policy ResponseMessagePolicy) map[string]any {
	out := map[string]any{
		"id":           sec.Request.ID,
		"method":       sec.Request.Method,
		"path":         sec.Request.Path,
		"content_type": sec.Request.ContentType,
		"body_size":    sec.Request.BodySize,
		"host":         sec.Request.Host,
	}
	if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
		out["query"] = sanitizeMap(stringMapToAny(sec.Request.Query), policy)
		out["headers"] = sanitizeMap(stringMapToAny(sec.Request.Headers), policy)
		out["params"] = sanitizeMap(stringMapToAny(sec.Request.Params), policy)
		out["user_agent"] = sanitizePublicText(sec.Request.UserAgent, policy)
	} else {
		out["query_keys"] = sortedStringKeys(sec.Request.Query)
		out["header_keys"] = sortedStringKeys(sec.Request.Headers)
		out["param_keys"] = sortedStringKeys(sec.Request.Params)
		if sec.Request.UserAgent != "" {
			out["user_agent_hash"] = publicValueHash(sec.Request.UserAgent)
		}
	}
	return out
}

func decisionLogNetwork(sec *Context, policy ResponseMessagePolicy) map[string]any {
	out := map[string]any{"country": sec.Network.Country, "country_code": sec.Network.CountryCode, "asn": sec.Network.ASN, "proxy": sec.Network.Proxy, "vpn": sec.Network.VPN, "tor": sec.Network.Tor, "reputation": sec.Network.Reputation, "intel_source": sec.Network.IntelSource, "intel_match_type": sec.Network.IntelMatchType}
	if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
		out["ip"] = sec.Network.IP
		out["previous_ip"] = sec.Network.PreviousIP
	} else {
		if sec.Network.IP != "" {
			out["ip_hash"] = publicValueHash(sec.Network.IP)
		}
		if sec.Network.PreviousIP != "" {
			out["previous_ip_hash"] = publicValueHash(sec.Network.PreviousIP)
		}
	}
	return out
}

func decisionLogIdentity(sec *Context, policy ResponseMessagePolicy) map[string]any {
	out := map[string]any{"type": sec.Identity.Type, "role": sec.Identity.Role, "roles": sec.Identity.Roles, "groups": sec.Identity.Groups, "tenant": sec.Identity.Tenant, "auth_method": sec.Identity.AuthMethod}
	if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
		out["id"] = sec.Identity.ID
		out["attrs"] = sanitizeMap(sec.Identity.Attrs, policy)
	} else if sec.Identity.ID != "" {
		out["id_hash"] = publicValueHash(sec.Identity.ID)
	}
	return out
}

func decisionLogTenant(sec *Context, policy ResponseMessagePolicy) map[string]any {
	out := map[string]any{"id": sec.Tenant.ID, "plan": sec.Tenant.Plan, "environment": sec.Tenant.Environment}
	if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
		out["metadata"] = sanitizeMap(sec.Tenant.Metadata, policy)
	}
	return out
}

func decisionLogBusiness(sec *Context, _ ResponseMessagePolicy) map[string]any {
	return map[string]any{"action": sec.Business.Action, "entity": sec.Business.Entity, "amount": sec.Business.Amount, "workflow": sec.Business.Workflow, "approval_level": sec.Business.ApprovalLevel, "sensitivity": sec.Business.Sensitivity, "outside_hours": sec.Business.OutsideHours, "holiday": sec.Business.Holiday}
}

func decisionLogFindings(findings []Finding, policy ResponseMessagePolicy) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		m := map[string]any{"id": f.ID, "type": f.Type, "severity": f.Severity, "confidence": f.Confidence, "risk": f.Risk, "message": sanitizePublicText(f.Message, policy), "stride": f.STRIDE, "mitre": f.MITRE, "threat_categories": f.ThreatCategories}
		if policy.IncludeValues && len(f.Fields) > 0 {
			m["fields"] = sanitizeMap(f.Fields, policy)
		} else if len(f.Fields) > 0 {
			m["field_keys"] = sortedAnyKeys(f.Fields)
		}
		out = append(out, m)
	}
	return out
}

func decisionLogEvidence(evidence []Evidence, policy ResponseMessagePolicy) []map[string]any {
	out := make([]map[string]any, 0, len(evidence))
	for _, e := range evidence {
		m := map[string]any{"type": e.Type, "id": e.ID, "message": sanitizePublicText(e.Message, policy)}
		if policy.IncludeValues && len(e.Fields) > 0 {
			m["fields"] = sanitizeMap(e.Fields, policy)
		} else if len(e.Fields) > 0 {
			m["field_keys"] = sortedAnyKeys(e.Fields)
		}
		out = append(out, m)
	}
	return out
}

func decisionLogActions(actions []ActionResult, policy ResponseMessagePolicy) []map[string]any {
	out := make([]map[string]any, 0, len(actions))
	for _, action := range actions {
		m := map[string]any{"id": action.ID, "type": action.Type, "status": action.Status, "at": action.At}
		if action.Error != "" {
			m["error"] = sanitizePublicText(action.Error, policy)
		}
		if policy.IncludeValues && len(action.Fields) > 0 {
			m["fields"] = sanitizeMap(action.Fields, policy)
		} else if len(action.Fields) > 0 {
			m["field_keys"] = sortedAnyKeys(action.Fields)
		}
		out = append(out, m)
	}
	return out
}

func stringMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedStringKeys(in map[string]string) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedAnyKeys(in map[string]any) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
