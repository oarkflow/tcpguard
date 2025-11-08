package tcpguard

import (
	"fmt"
	"strings"
	"sync"
)

type InMemoryMetricsCollector struct {
	counters   map[string]map[string]int64
	gauges     map[string]map[string]float64
	histograms map[string][]float64
	mu         sync.RWMutex
}

func NewInMemoryMetricsCollector() *InMemoryMetricsCollector {
	return &InMemoryMetricsCollector{
		counters:   make(map[string]map[string]int64),
		gauges:     make(map[string]map[string]float64),
		histograms: make(map[string][]float64),
	}
}

func (m *InMemoryMetricsCollector) IncrementCounter(name string, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(name, labels)
	if m.counters[key] == nil {
		m.counters[key] = make(map[string]int64)
	}
	labelKey := m.makeLabelKey(labels)
	m.counters[key][labelKey]++
}

func (m *InMemoryMetricsCollector) ObserveHistogram(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(name, labels)
	m.histograms[key] = append(m.histograms[key], value)
}

func (m *InMemoryMetricsCollector) SetGauge(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(name, labels)
	if m.gauges[key] == nil {
		m.gauges[key] = make(map[string]float64)
	}
	labelKey := m.makeLabelKey(labels)
	m.gauges[key][labelKey] = value
}

func (m *InMemoryMetricsCollector) makeKey(name string, labels map[string]string) string {
	return name
}

func (m *InMemoryMetricsCollector) makeLabelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return "default"
	}
	// Sort keys for consistency
	var keys []string
	for k := range labels {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

// GetCounterValue returns the current value of a counter (for testing/debugging)
func (m *InMemoryMetricsCollector) GetCounterValue(name string, labels map[string]string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(name, labels)
	labelKey := m.makeLabelKey(labels)
	if counters, exists := m.counters[key]; exists {
		return counters[labelKey]
	}
	return 0
}

// GetGaugeValue returns the current value of a gauge (for testing/debugging)
func (m *InMemoryMetricsCollector) GetGaugeValue(name string, value float64, labels map[string]string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(name, labels)
	labelKey := m.makeLabelKey(labels)
	if gauges, exists := m.gauges[key]; exists {
		return gauges[labelKey]
	}
	return 0
}

// HealthCheck performs a health check on the metrics collector
func (m *InMemoryMetricsCollector) HealthCheck() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Basic health check - ensure maps are accessible
	_ = len(m.counters)
	_ = len(m.gauges)
	_ = len(m.histograms)

	return nil
}

// ExportPrometheus exports metrics in Prometheus format
func (m *InMemoryMetricsCollector) ExportPrometheus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var output strings.Builder

	// Export counters
	for key, labelMap := range m.counters {
		for labelKey, value := range labelMap {
			output.WriteString(fmt.Sprintf("# HELP %s Counter\n", key))
			output.WriteString(fmt.Sprintf("# TYPE %s counter\n", key))
			output.WriteString(fmt.Sprintf("%s{%s} %d\n", key, labelKey, value))
		}
	}

	// Export gauges
	for key, labelMap := range m.gauges {
		for labelKey, value := range labelMap {
			output.WriteString(fmt.Sprintf("# HELP %s Gauge\n", key))
			output.WriteString(fmt.Sprintf("# TYPE %s gauge\n", key))
			output.WriteString(fmt.Sprintf("%s{%s} %f\n", key, labelKey, value))
		}
	}

	// Export histograms (simplified)
	for key, values := range m.histograms {
		if len(values) > 0 {
			sum := 0.0
			count := len(values)
			for _, v := range values {
				sum += v
			}
			output.WriteString(fmt.Sprintf("# HELP %s Histogram\n", key))
			output.WriteString(fmt.Sprintf("# TYPE %s histogram\n", key))
			output.WriteString(fmt.Sprintf("%s_sum %f\n", key, sum))
			output.WriteString(fmt.Sprintf("%s_count %d\n", key, count))
		}
	}

	return output.String()
}
