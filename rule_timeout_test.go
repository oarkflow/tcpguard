package tcpguard

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/tcpguard/internal/ruleexpr"
)

func TestRuleDeadlineContextOnlyForContextAwareWork(t *testing.T) {
	plain, err := ruleexpr.Compile(`request.method == "GET"`)
	if err != nil {
		t.Fatal(err)
	}
	if ruleNeedsDeadlineContext(&Rule{compiled: plain}) {
		t.Fatal("plain expression should use the allocation-free deadline check")
	}

	withFunction, err := ruleexpr.Compile(`timeout_probe()`)
	if err != nil {
		t.Fatal(err)
	}
	if !ruleNeedsDeadlineContext(&Rule{compiled: withFunction}) {
		t.Fatal("function expression must receive a deadline context")
	}
	if !ruleNeedsDeadlineContext(&Rule{Sequence: &SequenceTrigger{}}) {
		t.Fatal("sequence rule must receive a deadline context for store operations")
	}
}

func TestRuleEvalExceeded(t *testing.T) {
	if ruleEvalExceeded(time.Now(), time.Second) {
		t.Fatal("fresh evaluation should be within budget")
	}
	if !ruleEvalExceeded(time.Now().Add(-time.Second), time.Millisecond) {
		t.Fatal("expired evaluation should exceed budget")
	}
	if ruleEvalExceeded(time.Now().Add(-time.Second), 0) {
		t.Fatal("disabled evaluation budget should never expire")
	}
}

func TestRegisteredFunctionStillReceivesRuleDeadline(t *testing.T) {
	ruleexpr.RegisterFunction("tcpguard_test_rule_deadline", func(ruleexpr.EvalContext, ...any) (any, error) {
		time.Sleep(10 * time.Millisecond)
		return true, nil
	})
	guard, err := New(
		WithoutDefaultDetectors(),
		WithMode(Enforce),
		WithSafety(PolicySafety{MaxRuleEvalTime: time.Millisecond}),
		WithRule(Rule{
			ID:        "deadline-test",
			Status:    RuleActive,
			Triggers:  []string{"request.received"},
			Condition: "tcpguard_test_rule_deadline()",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := guard.Evaluate(context.Background(), Event{Type: "request.received"}, &Context{})
	if len(decision.MatchedRules) != 0 {
		t.Fatalf("timed-out rule unexpectedly matched: %#v", decision.MatchedRules)
	}
	if len(decision.Findings) == 0 {
		t.Fatal("timed-out rule should produce a failure finding")
	}
}
