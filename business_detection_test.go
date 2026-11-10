package tcpguard_test

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/tcpguard"
)

func TestPolicyCanReadContextRequestAndHeaders(t *testing.T) {
	guard, err := tcpguard.New(
		tcpguard.WithoutDefaultDetectors(),
		tcpguard.WithoutAudit(),
		tcpguard.WithRule(tcpguard.Rule{
			ID:        "header-context-case",
			Triggers:  []string{"request.received"},
			Condition: `context.user.id == "user-17" and request.header.x-api-key == "key-123" and header.x-tenant == "tenant-4" and request.path == "/payments/approve"`,
			Risk:      tcpguard.RiskSpec{Base: 90, Max: 100},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	sec := &tcpguard.Context{
		Request:  tcpguard.RequestContext{Path: "/payments/approve", Headers: map[string]string{"X-API-Key": "key-123", "X-Tenant": "tenant-4"}},
		Identity: tcpguard.IdentityContext{ID: "user-17"},
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	if len(decision.MatchedRules) != 1 || decision.MatchedRules[0] != "header-context-case" {
		t.Fatalf("matched rules = %v; want header-context-case", decision.MatchedRules)
	}
}

func TestBusinessDetectorUsesConfiguredHeaderAndRequestPathForDuplicatePayments(t *testing.T) {
	ctx := context.Background()
	store := tcpguard.NewMemoryStore()
	detector := tcpguard.BusinessAnomalyDetector{
		Store: store, Window: time.Minute,
		TransactionIDPath:   "request.query.payment_id",
		TransactionIDHeader: "X-Idempotency-Key",
	}
	event := tcpguard.Event{Type: "business.payment"}
	first := paymentContext("payment-884", "")
	findings, err := detector.Detect(ctx, first, event)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingAbsent(t, findings, "duplicate_transaction")

	// The configured request path can supply the transaction ID when the
	// header is absent. This is a separate realistic payment from the first.
	second := paymentContext("", "payment-885")
	findings, err = detector.Detect(ctx, second, event)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingAbsent(t, findings, "duplicate_transaction")

	replay := paymentContext("", "payment-885")
	findings, err = detector.Detect(ctx, replay, event)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "duplicate_transaction")
}

func TestBusinessDetectorRealRiskScenarios(t *testing.T) {
	ctx := context.Background()
	store := tcpguard.NewMemoryStore()
	detector := tcpguard.BusinessAnomalyDetector{
		Store: store, Window: time.Minute,
		AuthzFailureThreshold:   2,
		BodySizeThreshold:       1 << 20,
		ApprovalAmountThreshold: 10000,
		ServiceAllowlist:        []string{"payments-api"},
		ServiceIDHeader:         "X-Service-Name",
	}

	// Bulk upload crosses the configured request-body threshold.
	bulk := paymentContext("bulk-1", "")
	bulk.Request.BodySize = 2 << 20
	findings, err := detector.Detect(ctx, bulk, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "request_body_anomaly")

	// A high-value transfer without approval is flagged for a configured step-up.
	transfer := paymentContext("transfer-1", "")
	transfer.Business.Action = "payment.transfer"
	transfer.Business.Amount = 15000
	findings, err = detector.Detect(ctx, transfer, tcpguard.Event{Type: "business.payment", Fields: map[string]any{"approval_required": true}})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "approval_level_missing")

	// An unrecognized workload identity is flagged from the configured header.
	service := paymentContext("service-1", "")
	service.Identity.Type = "service"
	service.Request.Headers["x-service-name"] = "unknown-worker"
	findings, err = detector.Detect(ctx, service, tcpguard.Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "unknown_service_identity")

	// Repeated authorization denials for the same actor cross the threshold.
	actor := paymentContext("authz-1", "")
	actor.Identity.ID = "user-denied"
	if _, err := detector.Detect(ctx, actor, tcpguard.Event{Type: "authz.denied"}); err != nil {
		t.Fatal(err)
	}
	findings, err = detector.Detect(ctx, actor, tcpguard.Event{Type: "authz.denied"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "authorization_failure_velocity")

	// Role grants are compared against a deployment-defined privileged role list.
	findings, err = detector.Detect(ctx, actor, tcpguard.Event{Type: "security.privilege_changed", Fields: map[string]any{"old_role": "member", "new_role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	// Without privileged_roles configured, the built-in common role hierarchy
	// still recognizes member -> admin elevation.
	assertFinding(t, findings, "privilege_elevation")
}

func TestBusinessDetectorSensitiveRecordAccessVelocity(t *testing.T) {
	ctx := context.Background()
	detector := tcpguard.BusinessAnomalyDetector{
		Store:                    tcpguard.NewMemoryStore(),
		Window:                   time.Minute,
		SensitiveRecordThreshold: 5,
	}
	makeContext := func() *tcpguard.Context {
		return &tcpguard.Context{
			Identity: tcpguard.IdentityContext{ID: "reader-1"},
			Tenant:   tcpguard.TenantContext{ID: "tenant-1"},
			Business: tcpguard.BusinessContext{Sensitivity: "high"},
		}
	}
	event := tcpguard.Event{Type: "security.data_access", Fields: map[string]any{"records_count": 3}}
	first, err := detector.Detect(ctx, makeContext(), event)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingAbsent(t, first, "sensitive_data_access_velocity")
	second, err := detector.Detect(ctx, makeContext(), event)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, second, "sensitive_data_access_velocity")

	bulkEvent := tcpguard.Event{Type: "security.record_access", Fields: map[string]any{"sensitive": true, "records_count": 5}}
	bulk, err := detector.Detect(ctx, makeContext(), bulkEvent)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, bulk, "bulk_sensitive_data_access")
}

func TestBusinessDetectorUsesConfiguredPrivilegedRolesAndOnlyCountsDenials(t *testing.T) {
	ctx := context.Background()
	detector := tcpguard.BusinessAnomalyDetector{
		Store:                 tcpguard.NewMemoryStore(),
		AuthzFailureThreshold: 1,
		PrivilegedRoles:       []string{"risk_officer"},
	}
	privileged := &tcpguard.Context{
		Identity: tcpguard.IdentityContext{Role: "risk_officer"},
		Business: tcpguard.BusinessContext{OutsideHours: true},
	}
	findings, err := detector.Detect(ctx, privileged, tcpguard.Event{Type: "business.action"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "after_hours_admin_access")

	actor := &tcpguard.Context{Identity: tcpguard.IdentityContext{ID: "actor-1"}}
	findings, err = detector.Detect(ctx, actor, tcpguard.Event{Type: "authz.allowed", Fields: map[string]any{"status": "200"}})
	if err != nil {
		t.Fatal(err)
	}
	assertFindingAbsent(t, findings, "authorization_failure_velocity")
	findings, err = detector.Detect(ctx, actor, tcpguard.Event{Type: "authz.denied"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "authorization_failure_velocity")
}

func TestBusinessAnomalyConfigurationParsesHeaderAndFactSources(t *testing.T) {
	bundle, err := tcpguard.ParseTCPGuardBundle([]byte(`
detector "business-controls" {
  type business_anomaly
  transaction_id_header "X-Idempotency-Key"
  transaction_id_path "request.query.payment_id"
  service_id_header "X-Service-Name"
  service_allowlist ["payments-api", "billing-worker"]
  privileged_roles ["owner", "admin"]
}
`))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := tcpguard.New(tcpguard.WithBundle(bundle), tcpguard.WithoutAudit())
	if err != nil {
		t.Fatal(err)
	}
	sec := paymentContext("cfg-1", "")
	sec.Identity.Type = "service"
	sec.Identity.ID = ""
	sec.Request.Headers["x-service-name"] = "unlisted-worker"
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "business.payment"}, sec)
	assertFinding(t, decision.Findings, "unknown_service_identity")
}

func paymentContext(headerID, queryID string) *tcpguard.Context {
	return &tcpguard.Context{
		Request: tcpguard.RequestContext{
			Path: "/payments/transfer", Method: "POST",
			Headers: map[string]string{"x-idempotency-key": headerID},
			Query:   map[string]string{"payment_id": queryID},
		},
		Identity: tcpguard.IdentityContext{ID: "payer-1", Type: "user"},
		Tenant:   tcpguard.TenantContext{ID: "tenant-4"},
		Business: tcpguard.BusinessContext{Action: "payment.transfer", Amount: 100},
	}
}

func assertFindingAbsent(t *testing.T, findings []tcpguard.Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			t.Fatalf("unexpected finding %q", id)
		}
	}
}
