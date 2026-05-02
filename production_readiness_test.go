package tcpguard

import (
	"strings"
	"testing"
	"time"
)

func TestProductionReadinessBlocksUnsafeLaunch(t *testing.T) {
	store := newConfigAPITestStore(t)
	api := NewConfigAPI(store, WithConfigAPIUnsafePublicAccess(), WithConfigAPIMutationRateLimit(0, time.Minute))
	report := CheckProductionReadiness(ProductionReadinessConfig{
		Mode:                DeploymentProduction,
		ConfigAPI:           api,
		ConfigAPIAuthSecret: []byte("short"),
		BehindTrustedProxy:  true,
		RequireDurableState: true,
		RequireAuditEmitter: true,
		RequireSignedAuth:   true,
		CounterStore:        NewInMemoryCounterStore(),
		StateStore:          NewInMemoryStateStore(),
	})
	if report.Ready {
		t.Fatalf("Ready = true, want false")
	}
	joined := strings.Join(report.Errors, " ")
	for _, want := range []string{
		"unsafe public access",
		"signed auth secret",
		"trusted proxy CIDRs",
		"in-memory CounterStore",
		"in-memory StateStore",
		"audit event emitter",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("readiness errors missing %q: %#v", want, report.Errors)
		}
	}
}

func TestProductionReadinessAllowsHardenedConfigAPI(t *testing.T) {
	store := newConfigAPITestStore(t)
	api := NewConfigAPI(
		store,
		WithConfigAPIAuthz(NewDefaultConfigAPIAuthzEngine(), nil),
		WithConfigAPITrustedProxyCIDRs("127.0.0.1/32"),
		WithConfigAPICSRFToken("X-CSRF-Token", "csrf-secret"),
	)
	report := CheckProductionReadiness(ProductionReadinessConfig{
		Mode:                 DeploymentProduction,
		ConfigAPI:            api,
		ConfigAPIAuthSecret:  []byte("0123456789abcdef0123456789abcdef"),
		BehindTrustedProxy:   true,
		TrustedProxyCIDRs:    []string{"127.0.0.1/32"},
		RequireConfigVersion: true,
		RequireSignedAuth:    true,
	})
	if !report.Ready {
		t.Fatalf("Ready = false, errors = %#v", report.Errors)
	}
}
