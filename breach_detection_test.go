package tcpguard_test

import (
	"context"
	"testing"

	"github.com/oarkflow/tcpguard"
)

func TestDefaultGuardSurfacesBreachAndCompromiseEvents(t *testing.T) {
	guard, err := tcpguard.New(tcpguard.WithoutAudit())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		eventType string
		findingID string
	}{
		{"security.data_breach", "confirmed_data_breach"},
		{"security.credential_exposure", "credential_exposure_detected"},
		{"security.server_compromise", "server_compromise_detected"},
		{"security.breach_suspected", "suspected_security_breach"},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: tc.eventType}, &tcpguard.Context{})
			assertFinding(t, decision.Findings, tc.findingID)
		})
	}
	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "security.alert"}, &tcpguard.Context{})
	assertFindingAbsent(t, decision.Findings, "confirmed_data_breach")
}
