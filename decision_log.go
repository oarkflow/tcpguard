package tcpguard

import (
	"sort"
	"strings"
	"time"
)

// DecisionLogEntry builds an operator-facing structured log entry for a TCPGuard
// decision. The production default is intentionally compact: one searchable log
// line with the trigger, concise reason, action summary, request ID,
// audit/incident references, and safe entity references. Use ResponseMessagePolicy.LogLevel=full for local
// debugging or trusted SIEM sinks that need the full redacted decision context.
func DecisionLogEntry(sec *Context, decision Decision, policy ResponseMessagePolicy) map[string]any {
	policy = normalizeResponsePolicy(policy)
	if policy.LogLevel == DecisionLogNone {
		return map[string]any{}
	}
	if policy.LogLevel == DecisionLogFull {
		return fullDecisionLogEntry(sec, decision, policy)
	}
	entry := compactDecisionLogEntry(sec, decision, policy)
	if policy.LogLevel == DecisionLogStandard {
		if sec != nil {
			entry["request"] = decisionLogRequest(sec, policy)
			entry["identity"] = decisionLogIdentity(sec, policy)
			entry["network"] = decisionLogNetwork(sec, policy)
		}
		entry["policy"] = compactPolicyRef(decision)
		if decision.AuditEnvelope != nil {
			entry["audit"] = compactAuditRef(decision.AuditEnvelope)
		}
	}
	return entry
}

func compactDecisionLogEntry(sec *Context, decision Decision, policy ResponseMessagePolicy) map[string]any {
	entry := map[string]any{
		"event":           "tcpguard.http.decision",
		"allowed":         decision.Allowed,
		"effect":          decision.Effect,
		"severity":        decision.Severity,
		"risk_score":      decision.Risk.Score,
		"reason":          topPublicReason(sec, decision, policy),
		"triggered_rules": sanitizeStringSlice(decision.MatchedRules, forceRuleIDLogging(policy)),
		"findings":        compactFindingSummary(decision.Findings, policy),
	}
	if actions := compactActionSummary(decision.Actions, policy); len(actions.Executed) > 0 || actions.Skipped > 0 || actions.Failed > 0 {
		entry["actions"] = actions.Executed
		if actions.Skipped > 0 {
			entry["actions_skipped"] = actions.Skipped
		}
		if actions.Failed > 0 {
			entry["actions_failed"] = actions.Failed
		}
	}
	if len(decision.Incidents) > 0 {
		entry["incident_created"] = true
		if decision.Incidents[0].ID != "" {
			entry["incident_id"] = sanitizePublicText(decision.Incidents[0].ID, policy)
		}
	}
	if sec != nil {
		if sec.Request.ID != "" {
			entry["request_id"] = sec.Request.ID
		}
		if sec.Request.Method != "" {
			entry["method"] = sec.Request.Method
		}
		if sec.Request.Path != "" {
			entry["path"] = sec.Request.Path
		}
		if sec.Identity.ID != "" {
			if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
				entry["user_id"] = sanitizePublicText(sec.Identity.ID, policy)
			} else {
				entry["user_hash"] = publicValueHash(sec.Identity.ID)
			}
		}
		if sec.Identity.Role != "" {
			entry["role"] = sec.Identity.Role
		}
		if firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant) != "" {
			entry["tenant"] = firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant)
		}
		if sec.Network.IP != "" {
			if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
				entry["ip"] = sec.Network.IP
			} else {
				entry["ip_hash"] = publicValueHash(sec.Network.IP)
			}
		}
	}
	if decision.PolicyVersion != "" {
		entry["policy_version"] = decision.PolicyVersion
	}
	if decision.AuditEnvelope != nil {
		entry["audit_id"] = decision.AuditEnvelope.ID
	}
	removeEmptyLogValues(entry)
	return entry
}

func fullDecisionLogEntry(sec *Context, decision Decision, policy ResponseMessagePolicy) map[string]any {
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
	removeEmptyLogValues(entry)
	return entry
}

func forceRuleIDLogging(policy ResponseMessagePolicy) ResponseMessagePolicy {
	policy.IncludeRuleIDs = true
	return policy
}

func compactFindingSummary(findings []Finding, policy ResponseMessagePolicy) []map[string]any {
	seen := make(map[string]struct{}, len(findings))
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		id := firstNonEmpty(f.ID, f.Type)
		if id == "" {
			continue
		}
		key := id + "|" + string(f.Severity)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		m := map[string]any{"id": id, "type": firstNonEmpty(f.Type, f.ID), "severity": f.Severity, "risk": f.Risk}
		if f.Message != "" {
			m["message"] = sanitizePublicText(f.Message, policy)
		}
		out = append(out, m)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func compactEvidenceSummary(evidence []Evidence, policy ResponseMessagePolicy) []map[string]any {
	seen := make(map[string]struct{}, len(evidence))
	out := make([]map[string]any, 0, len(evidence))
	for _, e := range evidence {
		kind := firstNonEmpty(e.Type, e.ID)
		if kind == "" {
			continue
		}
		key := kind + "|" + e.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		m := map[string]any{"type": kind}
		if e.ID != "" {
			m["id"] = e.ID
		}
		if e.Message != "" && len(out) < 2 {
			m["message"] = sanitizePublicText(e.Message, policy)
		}
		out = append(out, m)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

type CompactActionSummary struct {
	Executed []string `json:"executed,omitempty"`
	Skipped  int      `json:"skipped,omitempty"`
	Failed   int      `json:"failed,omitempty"`
}

func compactActionSummary(actions []ActionResult, policy ResponseMessagePolicy) CompactActionSummary {
	_ = policy
	seen := make(map[string]struct{}, len(actions))
	out := CompactActionSummary{Executed: make([]string, 0, len(actions))}
	for _, action := range actions {
		status := strings.ToLower(strings.TrimSpace(action.Status))
		if status == "skipped" {
			out.Skipped++
			continue
		}
		if status != "" && status != "ok" && status != "success" && status != "executed" {
			out.Failed++
		}
		id := firstNonEmpty(action.Type, action.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out.Executed = append(out.Executed, id)
		if len(out.Executed) >= 6 {
			break
		}
	}
	return out
}

func compactPolicyRef(decision Decision) map[string]any {
	out := map[string]any{}
	if decision.PolicyVersion != "" {
		out["version"] = decision.PolicyVersion
	}
	if decision.ConfigHash != "" {
		out["config_hash"] = decision.ConfigHash
	}
	return out
}

func compactAuditRef(envelope *AuditEnvelope) map[string]any {
	if envelope == nil {
		return nil
	}
	return map[string]any{"id": envelope.ID, "sequence": envelope.Sequence}
}

func removeEmptyLogValues(m map[string]any) {
	for k, v := range m {
		switch x := v.(type) {
		case string:
			if x == "" {
				delete(m, k)
			}
		case []string:
			if len(x) == 0 {
				delete(m, k)
			}
		case []map[string]any:
			if len(x) == 0 {
				delete(m, k)
			}
		case map[string]any:
			if len(x) == 0 {
				delete(m, k)
			}
		case nil:
			delete(m, k)
		}
	}
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
	removeEmptyLogValues(out)
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
	removeEmptyLogValues(out)
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
	removeEmptyLogValues(out)
	return out
}

func decisionLogTenant(sec *Context, policy ResponseMessagePolicy) map[string]any {
	out := map[string]any{"id": sec.Tenant.ID, "plan": sec.Tenant.Plan, "environment": sec.Tenant.Environment}
	if policy.Environment == EnvironmentDevelopment || policy.Environment == EnvironmentTest || policy.IncludeValues {
		out["metadata"] = sanitizeMap(sec.Tenant.Metadata, policy)
	}
	removeEmptyLogValues(out)
	return out
}

func decisionLogBusiness(sec *Context, _ ResponseMessagePolicy) map[string]any {
	out := map[string]any{"action": sec.Business.Action, "entity": sec.Business.Entity, "amount": sec.Business.Amount, "workflow": sec.Business.Workflow, "approval_level": sec.Business.ApprovalLevel, "sensitivity": sec.Business.Sensitivity, "outside_hours": sec.Business.OutsideHours, "holiday": sec.Business.Holiday}
	removeEmptyLogValues(out)
	return out
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
		removeEmptyLogValues(m)
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
		removeEmptyLogValues(m)
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
		removeEmptyLogValues(m)
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
