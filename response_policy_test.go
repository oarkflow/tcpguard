package tcpguard_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/oarkflow/tcpguard"
)

func TestPublicDecisionBodyProductionRedactsSensitiveDetails(t *testing.T) {
	sec := &tcpguard.Context{}
	sec.Request.ID = "req-1"
	decision := tcpguard.Decision{
		Effect: tcpguard.DecisionBlock, Allowed: false,
		Risk: tcpguard.Risk{Score: 99, Confidence: 1}, Severity: tcpguard.SeverityCritical,
		MatchedRules: []string{"signed_webhook_replay"},
		Findings:     []tcpguard.Finding{{ID: "bad_signature", Type: "signature", Severity: tcpguard.SeverityCritical, Risk: 99, Message: "signature token=super-secret-token failed", Fields: map[string]any{"authorization": "Bearer secret", "tenant": "tenant-a"}}},
		Explanation:  "Blocked POST /webhook because signature token=super-secret-token failed.",
	}
	body := tcpguard.PublicDecisionBody(sec, decision, tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction))
	text := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(toJSONForTest(body)), "\\u003c", "<"), "\\u003e", ">"))
	if strings.Contains(text, "super-secret-token") || strings.Contains(text, "bearer secret") {
		t.Fatalf("production response leaked sensitive data: %s", text)
	}
	if strings.Contains(text, "signed_webhook_replay") {
		t.Fatalf("production response leaked rule id: %s", text)
	}
	if !strings.Contains(text, "request_id") || !strings.Contains(text, "request blocked") {
		t.Fatalf("production response did not include useful safe guidance: %s", text)
	}
}

func TestPublicDecisionBodyDevelopmentIncludesDetails(t *testing.T) {
	sec := &tcpguard.Context{}
	sec.Request.ID = "req-dev"
	decision := tcpguard.Decision{
		Effect: tcpguard.DecisionChallenge, Allowed: false,
		Risk: tcpguard.Risk{Score: 80, Confidence: 0.9}, Severity: tcpguard.SeverityHigh,
		MatchedRules: []string{"new_device_high_value_payment"},
		Findings:     []tcpguard.Finding{{ID: "new_device", Message: "new device for high-value payment", Fields: map[string]any{"device_id": "dev-1"}}},
		Explanation:  "Challenged request because new device for high-value payment.",
	}
	body := tcpguard.PublicDecisionBody(sec, decision, tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentDevelopment))
	text := toJSONForTest(body)
	if !strings.Contains(text, "new_device_high_value_payment") || !strings.Contains(text, "dev-1") {
		t.Fatalf("development response should include diagnostic details: %s", text)
	}
}

func toJSONForTest(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestPublicDecisionBodyProductionIsCompact(t *testing.T) {
	sec := &tcpguard.Context{}
	sec.Request.ID = "req-compact"
	decision := tcpguard.Decision{
		Effect: tcpguard.DecisionBlock, Allowed: false,
		Risk: tcpguard.Risk{Score: 90, Confidence: 0.8}, Severity: tcpguard.SeverityCritical,
		Findings: []tcpguard.Finding{{ID: "timestamp_skew", Type: "timestamp_skew", Severity: tcpguard.SeverityMedium, Risk: 65, Message: "request timestamp is outside allowed clock skew"}},
		Actions:  []tcpguard.ActionResult{{ID: "block", Type: "block", Status: "ok"}},
	}
	body := tcpguard.PublicDecisionBody(sec, decision, tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction))
	for _, noisy := range []string{"details", "risk_score", "confidence", "description", "support_url", "effect", "allowed", "severity"} {
		if _, ok := body[noisy]; ok {
			t.Fatalf("production body should not include noisy field %q: %#v", noisy, body)
		}
	}
	if body["reason"] != "request timestamp is outside allowed clock skew" || body["request_id"] != "req-compact" {
		t.Fatalf("production body should keep reason and request_id: %#v", body)
	}
}
