package tcpguard_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/oarkflow/tcpguard"
)

func TestDecisionLogEntryProductionIsCompact(t *testing.T) {
	sec := &tcpguard.Context{}
	sec.Request.ID = "req-log"
	sec.Request.Method = "POST"
	sec.Request.Path = "/api/v1/transfers"
	sec.Request.Headers = map[string]string{"Authorization": "Bearer secret-token", "X-TCPGuard-Signature": "abc"}
	sec.Network.IP = "127.0.0.1"
	sec.Identity.ID = "manager-1"
	sec.Identity.Role = "member"
	sec.Tenant.ID = "demo-bank"
	decision := tcpguard.Decision{
		Effect: tcpguard.DecisionBlock, Allowed: false,
		Risk: tcpguard.Risk{Score: 90, Confidence: 0.8}, Severity: tcpguard.SeverityCritical,
		MatchedRules: []string{"signed-transfer-replay-or-mitm"},
		Findings: []tcpguard.Finding{
			{ID: "timestamp_skew", Type: "timestamp_skew", Severity: tcpguard.SeverityMedium, Risk: 65, Message: "request timestamp is outside allowed clock skew"},
			{ID: "timestamp_skew", Type: "timestamp_skew", Severity: tcpguard.SeverityMedium, Risk: 65, Message: "request timestamp is outside allowed clock skew"},
		},
		Evidence:  []tcpguard.Evidence{{Type: "matched_rule", ID: "signed-transfer-replay-or-mitm"}, {Type: "rate", ID: "ip", Message: "rate counter updated"}},
		Actions:   []tcpguard.ActionResult{{ID: "block", Type: "block", Status: "ok"}, {ID: "notify_soc", Type: "event_bus", Status: "skipped", Error: "no endpoint configured"}},
		Incidents: []tcpguard.Incident{{ID: "incident_1", Severity: tcpguard.SeverityCritical, Status: "open"}},
	}
	entry := tcpguard.DecisionLogEntry(sec, decision, tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction))
	text := strings.ToLower(toJSONLogForTest(entry))
	for _, noisy := range []string{"authorization", "headers", "business", "trace", "audit_envelope", "config_hash", "manager-1", "127.0.0.1"} {
		if strings.Contains(text, noisy) {
			t.Fatalf("compact production log leaked noisy/sensitive field %q: %s", noisy, text)
		}
	}
	if !strings.Contains(text, "triggered_rules") || !strings.Contains(text, "actions") || !strings.Contains(text, "request_id") || !strings.Contains(text, "reason") {
		t.Fatalf("compact production log missed useful debugging fields: %s", text)
	}
	for _, repetitive := range []string{"message", "evidence", "component", "incidents"} {
		if _, ok := entry[repetitive]; ok {
			t.Fatalf("compact production log should omit repetitive/noisy field %q: %#v", repetitive, entry)
		}
	}
	findings, _ := entry["findings"].([]map[string]any)
	if len(findings) != 1 {
		t.Fatalf("compact production log should deduplicate repeated findings: %#v", entry["findings"])
	}
}

func toJSONLogForTest(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestDecisionLogEntryProductionActionSummaryIsNotNoisy(t *testing.T) {
	decision := tcpguard.Decision{
		Effect: tcpguard.DecisionBlock, Allowed: false, Severity: tcpguard.SeverityCritical,
		Actions: []tcpguard.ActionResult{
			{ID: "block", Type: "block", Status: "ok"},
			{ID: "incident_1", Type: "create_incident", Status: "ok"},
			{ID: "notify_soc", Type: "event_bus", Status: "skipped", Error: "no endpoint configured"},
		},
	}
	entry := tcpguard.DecisionLogEntry(nil, decision, tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction))
	text := toJSONLogForTest(entry)
	if strings.Contains(text, "no endpoint configured") || strings.Contains(text, "status") || strings.Contains(text, "event_bus") {
		t.Fatalf("compact actions should summarize, not dump action internals: %s", text)
	}
	if !strings.Contains(text, "block") || !strings.Contains(text, "create_incident") || !strings.Contains(text, "actions_skipped") {
		t.Fatalf("compact actions should keep executed action names and skipped count: %s", text)
	}
}
