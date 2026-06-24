package tcpguard

import "testing"

func TestAuditActionResultsCompact(t *testing.T) {
	in := []ActionResult{
		{ID: "block", Type: "block", Status: "ok", Fields: map[string]any{"debug": "value"}},
		{ID: "notify_soc", Type: "event_bus", Status: "skipped", Error: "no endpoint configured"},
		{ID: "notify_soc_2", Type: "event_bus", Status: "error", Error: "timeout", Fields: map[string]any{"payload": "secret"}},
	}
	out := auditActionResults(in)
	if len(out) != 2 {
		t.Fatalf("expected compact audit to keep executed and failed actions only, got %#v", out)
	}
	if out[0].Fields != nil || !out[0].At.IsZero() {
		t.Fatalf("audit action should omit noisy fields/timestamps: %#v", out[0])
	}
	if out[1].Error != "timeout" || out[1].Fields != nil {
		t.Fatalf("audit action should keep failure reason only, got %#v", out[1])
	}
}
