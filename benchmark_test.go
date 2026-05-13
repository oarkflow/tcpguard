package tcpguard_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/oarkflow/condition"
	"github.com/oarkflow/condition/tcpguard"
)

func BenchmarkGuardEvaluateCleanAllow(b *testing.B) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithMode(tcpguard.Enforce),
	)
	if err != nil {
		b.Fatal(err)
	}
	sec := benchContext("bench-clean", "/api/health", "user-1", "member")
	event := tcpguard.Event{Type: "request.received"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := guard.Evaluate(ctx, event, sec)
		if !decision.Allowed {
			b.Fatal("clean request should be allowed")
		}
	}
}

func BenchmarkGuardEvaluateCleanAllowLean(b *testing.B) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
	)
	if err != nil {
		b.Fatal(err)
	}
	sec := benchContext("bench-clean-lean", "/api/health", "user-1", "member")
	event := tcpguard.Event{Type: "request.received"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := guard.Evaluate(ctx, event, sec)
		if !decision.Allowed {
			b.Fatal("clean request should be allowed")
		}
	}
}

func BenchmarkGuardEvaluateDynamicRouteApproval(b *testing.B) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "dynamic-route",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Scope:     tcpguard.Scope{Paths: []string{"/api/users/:id/order/:order_id"}},
			Condition: `request.params.id != "" and request.params.order_id != ""`,
			Approval:  tcpguard.Approval{Required: true, Approvers: []string{"security-admin"}},
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	event := tcpguard.Event{Type: "request.received"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sec := benchContext("bench-route", "/api/users/user-1/order/order-9", "user-1", "member")
		decision := guard.Evaluate(ctx, event, sec)
		if decision.Effect != tcpguard.DecisionChallenge || len(decision.Approvals) == 0 {
			b.Fatalf("expected approval-gated challenge decision, got %#v", decision)
		}
	}
}

func BenchmarkGuardEvaluateDynamicRouteApprovalLean(b *testing.B) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "dynamic-route",
			Status:    tcpguard.RuleActive,
			Triggers:  []string{"request.received"},
			Scope:     tcpguard.Scope{Paths: []string{"/api/users/:id/order/:order_id"}},
			Condition: `request.params.id != "" and request.params.order_id != ""`,
			Approval:  tcpguard.Approval{Required: true, Approvers: []string{"security-admin"}},
			Risk:      tcpguard.RiskSpec{Base: 95, Max: 100},
			Severity:  []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
			Actions:   map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	event := tcpguard.Event{Type: "request.received"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sec := benchContext("bench-route-lean", "/api/users/user-1/order/order-9", "user-1", "member")
		decision := guard.Evaluate(ctx, event, sec)
		if decision.Effect != tcpguard.DecisionChallenge || len(decision.Approvals) == 0 {
			b.Fatalf("expected approval-gated challenge decision, got %#v", decision)
		}
	}
}

func BenchmarkGuardEvaluateDefaultDetectors(b *testing.B) {
	guard, err := tcpguard.New(tcpguard.WithMode(tcpguard.Enforce))
	if err != nil {
		b.Fatal(err)
	}
	sec := benchContext("bench-detectors", "/admin/users", "admin-1", "admin")
	sec.Business.OutsideHours = true
	event := tcpguard.Event{Type: "request.received"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := guard.Evaluate(ctx, event, sec)
		if len(decision.Findings) == 0 {
			b.Fatal("expected detector findings")
		}
	}
}

func BenchmarkMemoryStoreIncr(b *testing.B) {
	store := tcpguard.NewMemoryStore()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.Incr(ctx, "rate:ip:192.0.2.1", 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThreatIntelIndexedExactCIDRGlob(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "intel.txt")
	var data []byte
	data = append(data, []byte("198.51.100.7\n203.0.113.0/24\n192.0.2.*\n")...)
	for i := 0; i < 1000; i++ {
		data = append(data, []byte("10."+strconv.Itoa(i%255)+"."+strconv.Itoa((i/255)%255)+".*\n")...)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatal(err)
	}
	feed := &tcpguard.IndexedFileIntelFeed{Definition: tcpguard.IntelDefinition{
		ID:     "bench-intel",
		Type:   "file",
		Path:   "intel.txt",
		Match:  "network.ip",
		Fields: map[string]any{"network.ip.blacklisted": true, "network.reputation": float64(90)},
	}, BaseDir: dir}
	ctx := context.Background()
	sec := benchContext("bench-intel", "/public", "user-1", "member")
	sec.Network.IP = "203.0.113.42"
	sec.Extra = condition.MapFacts{}
	sec.Facts = condition.MapFacts{"network": map[string]any{"ip": sec.Network.IP}}
	if err := feed.Enrich(ctx, sec); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := feed.Enrich(ctx, sec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDatasourceRepeatedLookupCacheHit(b *testing.B) {
	sec := benchContext("bench-lookup", "/public", "user-1", "member")
	sec.Extra = condition.MapFacts{}
	sec.Facts = condition.MapFacts{"user": map[string]any{"id": sec.Identity.ID}}
	lookup := tcpguard.LookupDefinition{
		ID:     "user-profile",
		Source: "memory",
		Key:    `concat("profile:", user.id)`,
	}
	lc := tcpguard.NewLookupContext(sec, map[string]tcpguard.DataSource{
		"memory": tcpguard.MemoryDataSource{SourceID: "memory", Values: map[string]any{
			"profile:user-1": map[string]any{"risk": 42},
		}},
	}, []tcpguard.LookupDefinition{lookup}, tcpguard.DefaultPolicySafety())
	ctx := context.Background()
	if _, err := lc.Evaluate(ctx, "user-profile", ""); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := lc.Evaluate(ctx, "user-profile", "")
		if err != nil {
			b.Fatal(err)
		}
		if !result.Found {
			b.Fatal("expected cached lookup hit")
		}
	}
}

func BenchmarkGuardEvaluateLargeRulePack100(b *testing.B) {
	benchmarkGuardEvaluateLargeRulePack(b, 100)
}

func BenchmarkGuardEvaluateLargeRulePack1000(b *testing.B) {
	benchmarkGuardEvaluateLargeRulePack(b, 1000)
}

func BenchmarkGuardEvaluateLargeRulePack10000(b *testing.B) {
	benchmarkGuardEvaluateLargeRulePack(b, 10000)
}

func benchmarkGuardEvaluateLargeRulePack(b *testing.B, n int) {
	rules := make([]tcpguard.Rule, 0, n+1)
	for i := 0; i < n; i++ {
		rules = append(rules, tcpguard.Rule{
			ID:       "rule-miss-" + strconv.Itoa(i),
			Status:   tcpguard.RuleActive,
			Priority: i,
			Triggers: []string{"request.received"},
			Scope:    tcpguard.Scope{Paths: []string{"/miss/" + strconv.Itoa(i)}},
			Risk:     tcpguard.RiskSpec{Base: 10, Max: 100},
		})
	}
	rules = append(rules, tcpguard.Rule{
		ID:       "rule-hit",
		Status:   tcpguard.RuleActive,
		Priority: n + 1,
		Triggers: []string{"request.received"},
		Scope:    tcpguard.Scope{Paths: []string{"/hit"}},
		Risk:     tcpguard.RiskSpec{Base: 95, Max: 100},
		Severity: []tcpguard.SeverityRule{{Severity: tcpguard.SeverityCritical, Condition: `risk.score >= 90`}},
		Actions:  map[tcpguard.Severity][]tcpguard.ActionRef{tcpguard.SeverityCritical: {{ID: "block"}}},
	})
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithoutEntityProfiles(),
		tcpguard.WithMode(tcpguard.Enforce),
		tcpguard.WithRules(rules...),
	)
	if err != nil {
		b.Fatal(err)
	}
	sec := benchContext("bench-large-rules", "/hit", "user-1", "member")
	event := tcpguard.Event{Type: "request.received"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := guard.Evaluate(ctx, event, sec)
		if decision.Effect != tcpguard.DecisionBlock {
			b.Fatalf("effect=%s want block", decision.Effect)
		}
	}
}

func benchContext(id, path, userID, role string) *tcpguard.Context {
	return &tcpguard.Context{
		Request: tcpguard.RequestContext{
			ID:        id,
			Method:    http.MethodGet,
			Path:      path,
			Headers:   map[string]string{"User-Agent": "tcpguard-benchmark", "Host": "api.local"},
			Host:      "api.local",
			UserAgent: "tcpguard-benchmark",
		},
		Network:  tcpguard.NetworkContext{IP: "192.0.2.1"},
		Identity: tcpguard.IdentityContext{ID: userID, Role: role},
		Tenant:   tcpguard.TenantContext{ID: "bench"},
		Session:  tcpguard.SessionContext{ID: "sess-bench"},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
}
