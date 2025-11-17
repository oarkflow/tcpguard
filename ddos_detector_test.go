package tcpguard

import "testing"

func TestDetectHTTPFlood(t *testing.T) {
	snapshot := &TelemetrySnapshot{
		RequestPerSecond:   150,
		RequestPerMinute:   9000,
		PathDiversity:      0.05,
		UserAgentDiversity: 1,
	}
	cfg := attackConfig{
		thresholds: map[string]float64{
			"request_rate":   100,
			"path_diversity": 0.1,
			"ua_diversity":   2,
		},
	}
	outcome := detectHTTPFlood(detectionContext{snapshot: snapshot}, cfg)
	if !outcome.triggered {
		t.Fatalf("expected HTTP flood to trigger, got %+v", outcome)
	}
}

func TestDetectSYNFlood(t *testing.T) {
	snapshot := &TelemetrySnapshot{}
	snapshot.Additional = map[string]float64{
		"syn_rate":             150,
		"syn_completion_ratio": 0.05,
	}
	cfg := attackConfig{
		thresholds: map[string]float64{
			"rate":             100,
			"completion_ratio": 0.1,
		},
	}
	outcome := detectSYNFlood(detectionContext{snapshot: snapshot}, cfg)
	if !outcome.triggered {
		t.Fatalf("expected SYN flood to trigger, got %+v", outcome)
	}
}
