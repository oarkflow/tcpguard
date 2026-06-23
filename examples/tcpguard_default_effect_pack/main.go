package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/tcpguard"
)

func main() {
	// --- Allow by default (standard behavior) ---
	allowGuard, _ := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithDefaultEffect(tcpguard.DecisionAllow),
	)

	req := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req-1", Path: "/unknown", Method: "GET"},
		Security: map[string]any{},
		Rate:     map[string]any{},
		Runtime:  tcpguard.RuntimeContext{Timestamp: time.Now().UTC()},
	}

	allowResult := allowGuard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, req)
	fmt.Printf("Allow-by-default /unknown: effect=%s allowed=%v\n", allowResult.Effect, allowResult.Allowed)
	fmt.Printf("  Explanation: %s\n\n", allowResult.Explanation)

	// --- Deny by default ---
	denyGuard, _ := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithDefaultEffect(tcpguard.DecisionDeny),
	)

	denyResult := denyGuard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, req)
	fmt.Printf("Deny-by-default  /unknown: effect=%s allowed=%v\n", denyResult.Effect, denyResult.Allowed)
	fmt.Printf("  Explanation: %s\n\n", denyResult.Explanation)

	// --- Deny by default with a matching rule ---
	denyGuardWithRule, _ := tcpguard.New(
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithDefaultEffect(tcpguard.DecisionDeny),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "allow-health",
			Status:    tcpguard.RuleActive,
			Priority:  100,
			Triggers:  []string{"request.received"},
			Scope:     tcpguard.Scope{Paths: []string{"/health"}},
			Condition: `request.method == "GET"`,
			Risk:      tcpguard.RiskSpec{Base: 0, Max: 0},
		}),
	)

	healthReq := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: "req-2", Path: "/health", Method: "GET"},
		Security: map[string]any{},
		Rate:     map[string]any{},
		Runtime:  tcpguard.RuntimeContext{Timestamp: time.Now().UTC()},
	}

	matched := denyGuardWithRule.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, healthReq)
	fmt.Printf("Deny-by-default  /health  (rule matches): effect=%s allowed=%v\n", matched.Effect, matched.Allowed)
	fmt.Printf("  Matched rules: %v\n", matched.MatchedRules)
	fmt.Printf("  Explanation: %s\n", matched.Explanation)
}
