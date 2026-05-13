package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"

	"github.com/oarkflow/condition/tcpguard"
	"github.com/oarkflow/condition/tcpguard/bcl"
)

func main() {
	ctx := context.Background()
	dir := exampleDir()

	bundle, err := bcl.LoadTCPGuardBundleDir(ctx, dir)
	must("load tcpguard directory bundle", err)
	rootBundle, err := bcl.LoadTCPGuardBundleFile(ctx, filepath.Join(dir, "00-guard.bcl"))
	must("load tcpguard root bundle with includes", err)
	if len(rootBundle.Rules) != len(bundle.Rules) || len(rootBundle.Actions) != len(bundle.Actions) {
		log.Fatalf("root include bundle mismatch: dir rules=%d actions=%d root rules=%d actions=%d", len(bundle.Rules), len(bundle.Actions), len(rootBundle.Rules), len(rootBundle.Actions))
	}

	guard, err := tcpguard.New(tcpguard.WithBundle(bundle))
	must("create tcpguard", err)

	cases := []struct {
		name  string
		event string
		sec   *tcpguard.Context
	}{
		{
			name:  "global threat intel blocks bad IP",
			event: "request.received",
			sec: securityContext("req-bad-ip", http.MethodGet, "/api/v1/profile", "203.0.113.42", "user", "member", "sess-1", func(sec *tcpguard.Context) {
				sec.Tenant.ID = "bank"
			}),
		},
		{
			name:  "admin endpoint rule blocks critical after-hours change",
			event: "request.received",
			sec: securityContext("req-admin", http.MethodPost, "/admin/users", "192.0.2.10", "admin-1", "admin", "sess-admin", func(sec *tcpguard.Context) {
				sec.Tenant.ID = "bank"
				sec.Session.NewDevice = true
				sec.Business.OutsideHours = true
				sec.Business.Action = "admin.user.update"
			}),
		},
		{
			name:  "derived business trigger blocks high-value payment",
			event: "business.action",
			sec: securityContext("req-payment", http.MethodPost, "/api/v1/payments/approve", "192.0.2.11", "manager-1", "manager", "sess-manager", func(sec *tcpguard.Context) {
				sec.Tenant.ID = "bank"
				sec.Business.Action = "payment.approve"
				sec.Business.Amount = 1250000
				sec.Business.OutsideHours = true
			}),
		},
		{
			name:  "dynamic route params protect user order change",
			event: "request.received",
			sec: securityContext("req-order", http.MethodDelete, "/api/users/user-99/order/order-123", "192.0.2.13", "user-2", "member", "sess-order", func(sec *tcpguard.Context) {
				sec.Tenant.ID = "bank"
				sec.Business.Action = "order.cancel"
				sec.Business.OutsideHours = true
			}),
		},
		{
			name:  "session rule catches country change",
			event: "auth.login_success",
			sec: securityContext("req-login", http.MethodPost, "/login", "192.0.2.12", "user-2", "member", "sess-travel", func(sec *tcpguard.Context) {
				sec.Network.Country = "SG"
				sec.Session.PreviousCountry = "NP"
				sec.Session.CountryChanged = true
				sec.Session.NewDevice = true
			}),
		},
	}

	for _, tc := range cases {
		decision := guard.Evaluate(ctx, tcpguard.Event{Type: tc.event}, tc.sec)
		printSummary(tc.name, decision)
	}
}

func securityContext(requestID, method, path, ip, userID, role, sessionID string, mutate func(*tcpguard.Context)) *tcpguard.Context {
	sec := &tcpguard.Context{
		Request: tcpguard.RequestContext{
			ID:        requestID,
			Method:    method,
			Path:      path,
			Headers:   map[string]string{"User-Agent": "tcpguard-multi-file-example"},
			UserAgent: "tcpguard-multi-file-example",
		},
		Network:  tcpguard.NetworkContext{IP: ip},
		Identity: tcpguard.IdentityContext{ID: userID, Role: role},
		Session:  tcpguard.SessionContext{ID: sessionID},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	if mutate != nil {
		mutate(sec)
	}
	return sec
}

func printSummary(name string, decision tcpguard.Decision) {
	out := map[string]any{
		"case":          name,
		"effect":        decision.Effect,
		"risk":          decision.Risk.Score,
		"severity":      decision.Severity,
		"matched_rules": decision.MatchedRules,
		"actions":       actionIDs(decision.Actions),
		"findings":      findingIDs(decision.Findings),
		"approvals":     approvalSummaries(decision.Approvals),
	}
	data, err := json.MarshalIndent(out, "", "  ")
	must("marshal summary", err)
	fmt.Println(string(data))
}

func approvalSummaries(approvals []tcpguard.ApprovalRecord) []map[string]any {
	out := make([]map[string]any, 0, len(approvals))
	for _, approval := range approvals {
		out = append(out, map[string]any{
			"id":        approval.ID,
			"status":    approval.Status,
			"rule":      approval.RuleID,
			"approvers": approval.Approvers,
		})
	}
	return out
}

func actionIDs(actions []tcpguard.ActionResult) []string {
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		out = append(out, action.ID)
	}
	return out
}

func findingIDs(findings []tcpguard.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.ID)
	}
	return out
}

func exampleDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("resolve example directory")
	}
	return filepath.Dir(file)
}

func must(label string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}
}
