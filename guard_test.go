package tcpguard

import (
	"testing"
	"time"
)

func TestInMemoryCounterStore(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	// Test IncrementGlobal
	count, _, err := store.IncrementGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("IncrementGlobal failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected count 1, got %d", count)
	}

	// Test GetGlobal
	counter, err := store.GetGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("GetGlobal failed: %v", err)
	}
	if counter == nil {
		t.Fatal("Expected counter, got nil")
	}
	if counter.Count != 1 {
		t.Errorf("Expected count 1, got %d", counter.Count)
	}

	// Test ResetGlobal
	err = store.ResetGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("ResetGlobal failed: %v", err)
	}

	counter, err = store.GetGlobal("192.168.1.1")
	if err != nil {
		t.Fatalf("GetGlobal after reset failed: %v", err)
	}
	if counter != nil {
		t.Errorf("Expected nil after reset, got %v", counter)
	}
}

func TestInMemoryCounterStore_IncrementEndpoint(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	// Test IncrementEndpoint
	counter, err := store.IncrementEndpoint("192.168.1.1", "/api/login")
	if err != nil {
		t.Fatalf("IncrementEndpoint failed: %v", err)
	}
	if counter.Count != 1 {
		t.Errorf("Expected count 1, got %d", counter.Count)
	}
	if counter.Burst != 1 {
		t.Errorf("Expected burst 1, got %d", counter.Burst)
	}

	// Test GetEndpoint
	retrieved, err := store.GetEndpoint("192.168.1.1", "/api/login")
	if err != nil {
		t.Fatalf("GetEndpoint failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected counter, got nil")
	}
	if retrieved.Count != 1 {
		t.Errorf("Expected count 1, got %d", retrieved.Count)
	}
}

func TestInMemoryCounterStore_BanOperations(t *testing.T) {
	store := NewInMemoryCounterStore()
	defer store.StopCleanup()

	ban := &BanInfo{
		Until:      time.Now().Add(time.Hour),
		Permanent:  false,
		Reason:     "Test ban",
		StatusCode: 403,
	}

	// Test SetBan
	err := store.SetBan("192.168.1.1", ban)
	if err != nil {
		t.Fatalf("SetBan failed: %v", err)
	}

	// Test GetBan
	retrieved, err := store.GetBan("192.168.1.1")
	if err != nil {
		t.Fatalf("GetBan failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected ban info, got nil")
	}
	if retrieved.Reason != "Test ban" {
		t.Errorf("Expected reason 'Test ban', got '%s'", retrieved.Reason)
	}

	// Test DeleteBan
	err = store.DeleteBan("192.168.1.1")
	if err != nil {
		t.Fatalf("DeleteBan failed: %v", err)
	}

	retrieved, err = store.GetBan("192.168.1.1")
	if err != nil {
		t.Fatalf("GetBan after delete failed: %v", err)
	}
	if retrieved != nil {
		t.Errorf("Expected nil after delete, got %v", retrieved)
	}
}

func TestDefaultConfigValidator(t *testing.T) {
	validator := NewDefaultConfigValidator()

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				Rules: map[string]Rule{
					"test_rule": {
						Name:    "test_rule",
						Type:    "test",
						Enabled: true,
						Actions: []Action{
							{
								Type: "rate_limit",
								Response: Response{
									Status:  429,
									Message: "Rate limited",
								},
							},
						},
					},
				},
			},
			APIEndpoints: map[string]EndpointRules{
				"/api/test": {
					Name:      "test_endpoint",
					Endpoint:  "/api/test",
					RateLimit: RateLimit{RequestsPerMinute: 10},
					Actions: []Action{
						{
							Type: "rate_limit",
							Response: Response{
								Status:  429,
								Message: "Rate limited",
							},
						},
					},
				},
			},
		},
	}

	err := validator.Validate(config)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}
}

func TestInMemoryPipelineFunctionRegistry(t *testing.T) {
	reg := NewInMemoryPipelineFunctionRegistry()

	// Test Register and Get
	fn := func(ctx *Context) any {
		return "test_result"
	}

	reg.Register("test_function", fn)

	retrieved, exists := reg.Get("test_function")
	if !exists {
		t.Fatal("Expected function to exist")
	}

	if retrieved == nil {
		t.Fatal("Expected function, got nil")
	}

	// Test non-existent function
	_, exists = reg.Get("non_existent")
	if exists {
		t.Fatal("Expected function to not exist")
	}
}

func TestInMemoryMetricsCollector(t *testing.T) {
	collector := NewInMemoryMetricsCollector()

	labels := map[string]string{"endpoint": "/api/test", "method": "POST"}

	// Test IncrementCounter
	collector.IncrementCounter("requests_total", labels)

	value := collector.GetCounterValue("requests_total", labels)
	if value != 1 {
		t.Errorf("Expected counter value 1, got %d", value)
	}

	// Test ObserveHistogram
	collector.ObserveHistogram("request_duration", 0.5, labels)

	// Test SetGauge
	collector.SetGauge("active_connections", 10.0, labels)

	gaugeValue := collector.GetGaugeValue("active_connections", 10.0, labels)
	if gaugeValue != 10.0 {
		t.Errorf("Expected gauge value 10.0, got %f", gaugeValue)
	}
}
