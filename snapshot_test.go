package tcpguard

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/oarkflow/condition"
)

func TestRuleIndexCandidatesMatchLinearEligibility(t *testing.T) {
	rules := []Rule{
		{ID: "exact", Status: RuleActive, Priority: 100, Triggers: []string{"request.received"}, Scope: Scope{Paths: []string{"/public"}}},
		{ID: "prefix", Status: RuleActive, Priority: 90, Triggers: []string{"request.received"}, Scope: Scope{Paths: []string{"/admin/*"}}},
		{ID: "route", Status: RuleActive, Priority: 80, Triggers: []string{"request.received"}, Scope: Scope{Paths: []string{"/api/users/:id/order/:order_id"}}},
		{ID: "tenant", Status: RuleActive, Priority: 70, Triggers: []string{"request.received"}, Scope: Scope{Tenants: []string{"bank"}, Paths: []string{"*"}}},
		{ID: "method", Status: RuleActive, Priority: 65, Triggers: []string{"request.received"}, Scope: Scope{Methods: []string{http.MethodPost}, Paths: []string{"/api/users/:id/order/:order_id"}}},
		{ID: "auth", Status: RuleActive, Priority: 60, Triggers: []string{"auth.login_success"}},
		{ID: "fallback", Status: RuleActive, Priority: 50},
	}
	for i := range rules {
		if err := compileRule(&rules[i]); err != nil {
			t.Fatalf("compile rule %s: %v", rules[i].ID, err)
		}
	}
	idx := buildRuleIndex(rules)
	sec := &Context{
		Request: RequestContext{Path: "/api/users/u1/order/o9", Method: http.MethodGet},
		Tenant:  TenantContext{ID: "bank"},
		Facts:   condition.MapFacts{},
	}
	eventTypes := []string{"request.received"}
	gotIndexes := idx.candidatesFor(eventTypes, sec, rules)
	var got []string
	for _, index := range gotIndexes {
		if ok, err := scopeOnlyMatch(context.Background(), sec, eventTypes, &rules[index]); err == nil && ok {
			got = append(got, rules[index].ID)
		}
	}
	want := []string{"route", "tenant", "fallback"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates=%v want %v", got, want)
	}
	if sec.Request.Params["id"] != "u1" || sec.Request.Params["order_id"] != "o9" {
		t.Fatalf("route params not populated: %#v", sec.Request.Params)
	}
}

func TestRuleIndexCandidatesMatchLinearScanAcrossScopes(t *testing.T) {
	rules := []Rule{
		{ID: "exact-get", Status: RuleActive, Priority: 100, Triggers: []string{"request.received"}, Scope: Scope{Methods: []string{http.MethodGet}, Paths: []string{"/public"}}},
		{ID: "exact-post", Status: RuleActive, Priority: 99, Triggers: []string{"request.received"}, Scope: Scope{Methods: []string{http.MethodPost}, Paths: []string{"/public"}}},
		{ID: "prefix-admin", Status: RuleActive, Priority: 90, Triggers: []string{"request.received"}, Scope: Scope{Roles: []string{"admin"}, Paths: []string{"/admin/*"}}},
		{ID: "route-tenant", Status: RuleActive, Priority: 80, Triggers: []string{"request.received"}, Scope: Scope{Tenants: []string{"bank"}, Paths: []string{"/api/users/:id/order/:order_id"}}},
		{ID: "auth-only", Status: RuleActive, Priority: 70, Triggers: []string{"auth.login_success"}, Scope: Scope{Paths: []string{"*"}}},
		{ID: "fallback", Status: RuleActive, Priority: 60},
	}
	for i := range rules {
		if err := compileRule(&rules[i]); err != nil {
			t.Fatalf("compile rule %s: %v", rules[i].ID, err)
		}
	}
	idx := buildRuleIndex(rules)
	cases := []struct {
		name  string
		sec   *Context
		event []string
	}{
		{name: "get-public", sec: &Context{Request: RequestContext{Method: http.MethodGet, Path: "/public"}, Facts: condition.MapFacts{}}, event: []string{"request.received"}},
		{name: "post-public", sec: &Context{Request: RequestContext{Method: http.MethodPost, Path: "/public"}, Facts: condition.MapFacts{}}, event: []string{"request.received"}},
		{name: "admin-prefix", sec: &Context{Request: RequestContext{Method: http.MethodGet, Path: "/admin/users"}, Identity: IdentityContext{Role: "admin"}, Facts: condition.MapFacts{}}, event: []string{"request.received"}},
		{name: "tenant-route", sec: &Context{Request: RequestContext{Method: http.MethodGet, Path: "/api/users/u1/order/o1"}, Tenant: TenantContext{ID: "bank"}, Facts: condition.MapFacts{}}, event: []string{"request.received"}},
		{name: "auth-event", sec: &Context{Request: RequestContext{Method: http.MethodGet, Path: "/anything"}, Facts: condition.MapFacts{}}, event: []string{"auth.login_success"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			indexed := idx.candidatesFor(tc.event, tc.sec, rules)
			linear := idx.candidatesForIndexed(tc.event, tc.sec, rules, false)
			got := matchingRuleIDs(t, rules, indexed, tc.sec, tc.event)
			want := matchingRuleIDs(t, rules, linear, tc.sec, tc.event)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("indexed=%v linear=%v", got, want)
			}
		})
	}
}

func matchingRuleIDs(t *testing.T, rules []Rule, indexes []int, sec *Context, eventTypes []string) []string {
	t.Helper()
	var out []string
	for _, index := range indexes {
		ok, err := scopeOnlyMatch(context.Background(), sec, eventTypes, &rules[index])
		if err != nil {
			t.Fatalf("scope match: %v", err)
		}
		if ok {
			out = append(out, rules[index].ID)
		}
	}
	return out
}

func scopeOnlyMatch(ctx context.Context, sec *Context, eventTypes []string, rule *Rule) (bool, error) {
	if len(rule.Triggers) > 0 && !anyStringIn(eventTypes, rule.Triggers) {
		return false, nil
	}
	return scopeMatches(rule, sec), nil
}

func TestIndexedFileIntelFeedMatchesExactCIDRAndGlob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.txt")
	if err := os.WriteFile(path, []byte("198.51.100.7\n203.0.113.0/24\n192.0.2.*\n"), 0o600); err != nil {
		t.Fatalf("write intel: %v", err)
	}
	feed := &IndexedFileIntelFeed{Definition: IntelDefinition{
		ID:     "bad-ip",
		Type:   "file",
		Path:   "intel.txt",
		Match:  "network.ip",
		Fields: map[string]any{"network.ip.blacklisted": true, "network.reputation": float64(90)},
	}, BaseDir: dir}
	for _, ip := range []string{"198.51.100.7", "203.0.113.42", "192.0.2.99"} {
		sec := &Context{Network: NetworkContext{IP: ip}, Extra: condition.MapFacts{}, Facts: condition.MapFacts{}}
		sec.rebuildFacts()
		if err := feed.Enrich(context.Background(), sec); err != nil {
			t.Fatalf("enrich %s: %v", ip, err)
		}
		if sec.Network.Reputation != 90 {
			t.Fatalf("ip %s reputation=%v want 90", ip, sec.Network.Reputation)
		}
		if value, ok := sec.Facts.Get("network.ip.blacklisted"); !ok || value != true {
			t.Fatalf("ip %s blacklist fact=%v ok=%v", ip, value, ok)
		}
		if sec.Network.IntelSource != "bad-ip" || sec.Network.IntelMatchType == "" || sec.Network.IntelConfidence == 0 {
			t.Fatalf("ip %s missing intel metadata: %#v", ip, sec.Network)
		}
	}
}

func TestRateDetectorAlgorithms(t *testing.T) {
	for _, algorithm := range []RateAlgorithm{RateFixedWindow, RateSlidingWindow, RateTokenBucket} {
		store := NewMemoryStore()
		detector := NewRateDetectorWithAlgorithm(store, algorithm)
		detector.IPLimit = 2
		detector.Window = time.Minute
		sec := &Context{Network: NetworkContext{IP: "192.0.2.10"}, Rate: map[string]any{}, Security: map[string]any{}}
		for i := 0; i < 3; i++ {
			findings, err := detector.Detect(context.Background(), sec, Event{Type: "request.received"})
			if err != nil {
				t.Fatalf("%s detect: %v", algorithm, err)
			}
			if i == 2 && len(findings) == 0 {
				t.Fatalf("%s third request should exceed limit", algorithm)
			}
		}
	}
}
