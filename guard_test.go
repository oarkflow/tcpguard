package tcpguard

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestRequestCountConditionRule(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"

	guard := &Guard{
		requestTimes: make(map[string][]time.Time),
		bannedIPs:    make(map[string]BanEntry),
	}

	// Build a GenericRule that uses the request_count condition
	rule := &GenericRule{
		name: "/api_rate",
		conditions: []ConditionConfig{
			{
				Type: "request_count",
				Config: map[string]any{
					"uri":       "/api/",
					"methods":   []any{"GET"},
					"threshold": float64(2), // trigger after more than 2 requests
					"unit":      "second",
					"operator":  ">",
				},
			},
		},
		actions: []ActionRef{{Name: "test_action"}},
	}

	// First request: count=1 -> no anomaly
	anomaly, acts, err := rule.Check(context.Background(), req, guard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if anomaly {
		t.Fatalf("unexpected anomaly on first request")
	}
	if len(acts) != 0 {
		t.Fatalf("expected no actions on first request, got: %v", acts)
	}

	// Second request: count=2 -> no anomaly (operator > 2)
	anomaly, acts, err = rule.Check(context.Background(), req, guard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if anomaly {
		t.Fatalf("unexpected anomaly on second request")
	}

	// Third request: count=3 -> anomaly
	anomaly, acts, err = rule.Check(context.Background(), req, guard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !anomaly {
		t.Fatalf("expected anomaly on third request")
	}
	if len(acts) != 1 || acts[0].Name != "test_action" {
		t.Fatalf("expected action test_action, got: %v", acts)
	}

	// ensure the requestTimes window respects unit: wait longer than unit and the count should reset
	time.Sleep(1100 * time.Millisecond)
	anomaly, acts, err = rule.Check(context.Background(), req, guard)
	if err != nil {
		t.Fatalf("unexpected error after sleep: %v", err)
	}
	if anomaly {
		t.Fatalf("expected no anomaly after time window reset")
	}
}
