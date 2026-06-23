package tcpguard_test

import (
	"testing"

	"github.com/oarkflow/tcpguard"
)

func TestLintBundleReportsDuplicateRuleID(t *testing.T) {
	bundle := tcpguard.Bundle{Rules: []tcpguard.Rule{{ID: "same", Status: tcpguard.RuleActive, Triggers: []string{"request.received"}}, {ID: "same", Status: tcpguard.RuleActive, Triggers: []string{"request.received"}}}}
	report := tcpguard.LintBundle(bundle)
	if report.Valid {
		t.Fatalf("expected invalid report")
	}
	found := false
	for _, issue := range report.Issues {
		if issue.Code == "duplicate_rule_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected duplicate_rule_id issue, got %#v", report.Issues)
	}
}

func TestRegisteredRateDetectorFromBundle(t *testing.T) {
	guard, err := tcpguard.New(tcpguard.WithBundle(tcpguard.Bundle{Detectors: []tcpguard.DetectorDefinition{{ID: "custom-rate", Type: "rate", Fields: map[string]any{"ip_limit": int64(1)}}}}))
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Evaluate(nil, tcpguard.Event{Type: "request.received"}, &tcpguard.Context{Network: tcpguard.NetworkContext{IP: "127.0.0.1"}, Security: map[string]any{}, Rate: map[string]any{}})
	if decision.Effect == "" {
		t.Fatalf("expected decision")
	}
}
