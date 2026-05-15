package tcpguard_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/oarkflow/tcpguard"
)

func TestAbuseDetectorAuthSignals(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	detector := tcpguard.NewAbuseDetector(store)
	detector.AuthIPFailureThreshold = 2
	detector.AuthUserFailureThreshold = 2
	detector.PasswordSprayUserThreshold = 2
	ctx := context.Background()

	sec := abuseContext("req1", "203.0.113.10", "user-1", "/login")
	if _, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "auth.login_failed"}); err != nil {
		t.Fatal(err)
	}
	sec = abuseContext("req2", "203.0.113.10", "user-2", "/login")
	findings, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "auth.login_failed"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "credential_stuffing")
	assertFinding(t, findings, "password_spray")
	if got, ok := sec.Facts.Get("abuse.auth.ip_failures"); !ok || got.(int64) != 2 {
		t.Fatalf("abuse.auth.ip_failures=%v found=%v", got, ok)
	}
	if got, ok := sec.Facts.Get("abuse.auth.distinct_users"); !ok || got.(int64) != 2 {
		t.Fatalf("abuse.auth.distinct_users=%v found=%v", got, ok)
	}
}

func TestAbuseDetectorAccountTakeoverAndThreatCategories(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	guard, err := tcpguard.New(
		tcpguard.WithBundle(tcpguard.Bundle{ThreatModels: []tcpguard.ThreatModelDefinition{tcpguard.DefaultAbuseThreatModel()}}),
		tcpguard.WithDetector(tcpguard.AbuseDetector{Store: store, ProfileRiskThreshold: 50}),
		tcpguard.WithoutDefaultDetectors(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sec := abuseContext("req_ato", "198.51.100.10", "user-ato", "/account")
	sec.Session.NewDevice = true
	sec.Session.PreviousCountry = "US"
	sec.Network.Country = "NP"
	decision := guard.Evaluate(ctx, tcpguard.Event{Type: "auth.login_success"}, sec)
	assertFinding(t, decision.Findings, "account_takeover_risk")
	for _, finding := range decision.Findings {
		if finding.ID == "account_takeover_risk" {
			if len(finding.ThreatCategories["abuse-default"]) == 0 {
				t.Fatalf("threat categories missing: %#v", finding)
			}
			if len(finding.STRIDE) != 0 {
				t.Fatalf("abuse model should not be forced into STRIDE: %#v", finding.STRIDE)
			}
		}
	}
}

func TestAbuseDetectorAPIKeyScanningExportAndPaymentVelocity(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	detector := tcpguard.NewAbuseDetector(store)
	detector.APIKeyIPThreshold = 2
	detector.ScanPathThreshold = 2
	detector.ExportThreshold = 2
	detector.PaymentUserAmountThreshold = 100
	detector.PaymentTenantAmountThreshold = 150
	ctx := context.Background()

	sec := abuseContext("req_api_1", "203.0.113.1", "user-1", "/api/a")
	sec.Request.Headers = map[string]string{"X-API-Key": "key-1"}
	if _, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"}); err != nil {
		t.Fatal(err)
	}
	sec = abuseContext("req_api_2", "203.0.113.2", "user-1", "/api/b")
	sec.Request.Headers = map[string]string{"X-API-Key": "key-1"}
	findings, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "api_key_ip_spread")
	assertFinding(t, findings, "endpoint_scanning")
	if got, ok := sec.Facts.Get("abuse.api_key.distinct_ips"); !ok || got.(int64) != 2 {
		t.Fatalf("abuse.api_key.distinct_ips=%v found=%v", got, ok)
	}

	sec = abuseContext("req_export_1", "203.0.113.3", "exporter", "/api/reports/export")
	sec.Business.Action = "export_report"
	if _, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"}); err != nil {
		t.Fatal(err)
	}
	sec = abuseContext("req_export_2", "203.0.113.3", "exporter", "/api/reports/export")
	sec.Business.Action = "export_report"
	findings, err = detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "export_velocity")

	sec = abuseContext("req_pay_1", "203.0.113.4", "payer", "/api/payments")
	sec.Tenant.ID = "tenant-a"
	sec.Business.Action = "payment"
	sec.Business.Amount = 60
	if _, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"}); err != nil {
		t.Fatal(err)
	}
	sec = abuseContext("req_pay_2", "203.0.113.4", "payer", "/api/payments")
	sec.Tenant.ID = "tenant-a"
	sec.Business.Action = "payment"
	sec.Business.Amount = 100
	findings, err = detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "payment_velocity")
	assertFinding(t, findings, "tenant_payment_velocity")
	if got, ok := sec.Facts.Get("abuse.payment.user_amount"); !ok || got.(float64) != 160 {
		t.Fatalf("abuse.payment.user_amount=%v found=%v", got, ok)
	}
}

func TestAbuseDetectorApplicationFunctionAndAdminSignals(t *testing.T) {
	store := tcpguard.NewMemoryStore()
	detector := tcpguard.NewAbuseDetector(store)
	detector.FunctionInvokeThreshold = 2
	detector.UserAgentRotationThreshold = 2
	detector.APIKeyUserThreshold = 2
	ctx := context.Background()

	sec := abuseContext("req_app", "203.0.113.20", "probe", "/search")
	sec.Request.Query = map[string]string{"q": "' OR '1'='1 UNION SELECT password FROM users"}
	findings, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "injection_probe")
	if got, ok := sec.Facts.Get("abuse.application.injection_probe"); !ok || got != true {
		t.Fatalf("abuse.application.injection_probe=%v found=%v", got, ok)
	}

	sec = abuseContext("req_fn_1", "203.0.113.21", "fn-user", "/api/v1/functions/reconcile")
	if _, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"}); err != nil {
		t.Fatal(err)
	}
	sec = abuseContext("req_fn_2", "203.0.113.21", "fn-user", "/api/v1/functions/reconcile")
	findings, err = detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "function_invocation_velocity")
	if got, ok := sec.Facts.Get("abuse.fn.invocations"); !ok || got.(int64) != 2 {
		t.Fatalf("abuse.fn.invocations=%v found=%v", got, ok)
	}

	sec = abuseContext("req_key_1", "203.0.113.22", "api-user-1", "/api/data")
	sec.Request.Headers = map[string]string{"X-API-Key": "shared-user-key"}
	if _, err := detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"}); err != nil {
		t.Fatal(err)
	}
	sec = abuseContext("req_key_2", "203.0.113.22", "api-user-2", "/api/data")
	sec.Request.Headers = map[string]string{"X-API-Key": "shared-user-key"}
	findings, err = detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "api_key_user_spread")

	sec = abuseContext("req_admin", "203.0.113.23", "admin-1", "/admin/users/user-2/disable")
	sec.Identity.Role = "admin"
	sec.Business.Action = "user.disable"
	sec.Business.OutsideHours = true
	findings, err = detector.Detect(ctx, sec, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "destructive_admin_abuse")
}

func abuseContext(requestID, ip, user, path string) *tcpguard.Context {
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{ID: requestID, Method: http.MethodPost, Path: path, Headers: map[string]string{}, UserAgent: "Mozilla/5.0"},
		Network:  tcpguard.NetworkContext{IP: ip},
		Identity: tcpguard.IdentityContext{ID: user},
		Runtime:  tcpguard.RuntimeContext{Timestamp: time.Now().UTC()},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	return sec
}

func assertFinding(t *testing.T, findings []tcpguard.Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			return
		}
	}
	t.Fatalf("finding %q not found in %#v", id, findings)
}
