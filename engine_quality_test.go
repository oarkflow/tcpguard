package tcpguard_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/oarkflow/tcpguard"
)

type failingEnricher struct{}

type denyingAuthzProvider struct{}
type failingAuthzProvider struct{}

func (denyingAuthzProvider) Authorize(context.Context, tcpguard.AuthzRequest) (tcpguard.AuthzDecision, error) {
	return tcpguard.AuthzDecision{Allowed: false, Evidence: tcpguard.AuthzEvidence{Reason: "denied"}}, nil
}

func (failingAuthzProvider) Authorize(context.Context, tcpguard.AuthzRequest) (tcpguard.AuthzDecision, error) {
	return tcpguard.AuthzDecision{}, errors.New("sensitive authorization backend detail")
}

func (failingEnricher) ID() string { return "test-enricher" }
func (failingEnricher) Enrich(context.Context, *tcpguard.Context) error {
	return errors.New("sensitive backend detail")
}

func TestMemoryStoreAtomicCapabilities(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	const workers = 64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Incr(context.Background(), "counter", 0); err != nil {
				t.Errorf("Incr: %v", err)
			}
		}()
	}
	wg.Wait()
	value, found, err := store.Get(context.Background(), "counter")
	if err != nil || !found || string(value) != "64" {
		t.Fatalf("counter=%q found=%t err=%v, want 64", value, found, err)
	}

	wins := 0
	for i := 0; i < workers; i++ {
		won, err := store.SetNX(context.Background(), "nonce", []byte("accepted"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if won {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("SetNX winners=%d, want exactly one", wins)
	}
}

func TestMalformedSequenceStateFailsClosed(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	if err := store.Set(context.Background(), "sequence:sequence-rule:user:user-1", []byte("not-json"), 0); err != nil {
		t.Fatal(err)
	}
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithStore(store),
		tcpguard.WithRule(tcpguard.Rule{
			ID:       "sequence-rule",
			Status:   tcpguard.RuleActive,
			Sequence: &tcpguard.SequenceTrigger{Steps: []tcpguard.SequenceStep{{Event: "request.received"}}},
			Risk:     tcpguard.RiskSpec{Base: 95},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{Identity: tcpguard.IdentityContext{ID: "user-1"}})
	if decision.Effect != tcpguard.DecisionBlock || decision.Allowed {
		t.Fatalf("corrupt sequence state must fail closed: effect=%s allowed=%t", decision.Effect, decision.Allowed)
	}
}

func TestAuthzDenialFailsClosedWhenItRemovesTheOnlyRule(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithAuthzProvider(denyingAuthzProvider{}),
		tcpguard.WithRule(tcpguard.Rule{
			ID:          "protected-route",
			Status:      tcpguard.RuleActive,
			Triggers:    []string{"request.received"},
			AuthzPolicy: "route-access",
			Risk:        tcpguard.RiskSpec{Base: 20},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{})
	if decision.Effect != tcpguard.DecisionBlock || decision.Allowed {
		t.Fatalf("authorization denial must block: effect=%s allowed=%t", decision.Effect, decision.Allowed)
	}
}

func TestAuthzFailureIsSanitizedAndFailsClosed(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithAuthzProvider(failingAuthzProvider{}),
		tcpguard.WithRule(tcpguard.Rule{ID: "protected-route", Status: tcpguard.RuleActive, Triggers: []string{"request.received"}, AuthzPolicy: "route-access"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{})
	if decision.Effect != tcpguard.DecisionBlock || decision.Allowed {
		t.Fatalf("authorization error must block: effect=%s allowed=%t", decision.Effect, decision.Allowed)
	}
	for _, finding := range decision.Findings {
		if strings.Contains(finding.Message, "sensitive authorization backend detail") {
			t.Fatal("authorization backend error leaked into decision findings")
		}
	}
}

func TestEnforceBlocksAndRedactsEvaluationFailure(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithEnricher(failingEnricher{}),
	)
	if err != nil {
		t.Fatal(err)
	}

	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{})
	if decision.Effect != tcpguard.DecisionBlock || decision.Allowed {
		t.Fatalf("evaluation failure must block in enforce mode: effect=%s allowed=%t", decision.Effect, decision.Allowed)
	}
	found := false
	for _, finding := range decision.Findings {
		if finding.Type == "evaluation_error" && strings.HasPrefix(finding.ID, "enricher_error_") {
			found = true
			if strings.Contains(finding.Message, "sensitive backend detail") {
				t.Fatal("internal component error leaked into the decision")
			}
		}
	}
	if !found {
		t.Fatalf("expected sanitized evaluation error finding, got %#v", decision.Findings)
	}
}

func TestCanceledRuleEvaluationFailsClosed(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "request-method",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Condition: `request.method == "GET"`,
			Risk:      tcpguard.RiskSpec{Base: 95},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decision := guard.Evaluate(ctx, tcpguard.Event{Type: "request.received"}, &tcpguard.Context{Request: tcpguard.RequestContext{Method: "GET"}})
	if decision.Effect != tcpguard.DecisionBlock || decision.Allowed {
		t.Fatalf("canceled policy evaluation must block: effect=%s allowed=%t", decision.Effect, decision.Allowed)
	}
}

func TestOverlappingRulesRetainPriorityOrderAndHighestRisk(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRules(
			tcpguard.Rule{ID: "priority-first", Priority: 20, Triggers: []string{"request.received"}, Risk: tcpguard.RiskSpec{Base: 55}},
			tcpguard.Rule{ID: "risk-highest", Priority: 10, Triggers: []string{"request.received"}, Risk: tcpguard.RiskSpec{Base: 95}},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, &tcpguard.Context{})
	if len(decision.MatchedRules) != 2 || decision.MatchedRules[0] != "priority-first" || decision.MatchedRules[1] != "risk-highest" {
		t.Fatalf("matched rule order=%v, want priority order", decision.MatchedRules)
	}
	if decision.Risk.Score != 95 || decision.Effect != tcpguard.DecisionBlock {
		t.Fatalf("decision risk/effect=%v/%s, want 95/block", decision.Risk.Score, decision.Effect)
	}
}

func TestLintReportsMatchingRulesWithDifferentActions(t *testing.T) {
	bundle := tcpguard.Bundle{Rules: []tcpguard.Rule{
		{ID: "first", Triggers: []string{"request.received"}, Condition: `request.method == "POST"`, Actions: map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityHigh: {{ID: "block"}}}},
		{ID: "second", Triggers: []string{"request.received"}, Condition: `request.method == "POST"`, Actions: map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityHigh: {{ID: "throttle"}}}},
	}}
	report := tcpguard.LintBundle(bundle)
	for _, issue := range report.Issues {
		if issue.Code == "matching_rules_different_actions" && issue.Target == "second" {
			return
		}
	}
	t.Fatalf("expected matching_rules_different_actions warning, got %#v", report.Issues)
}
