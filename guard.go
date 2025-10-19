package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/ip"
)

type AnomalyConfig struct {
	AnomalyDetectionRules AnomalyDetectionRules `json:"anomalyDetectionRules"`
}

type AnomalyDetectionRules struct {
	Global       GlobalRules              `json:"global"`
	APIEndpoints map[string]EndpointRules `json:"apiEndpoints"`
}

type GlobalRules struct {
	Rules               map[string]Rule `json:"rules"`
	AllowCIDRs          []string        `json:"allowCIDRs,omitempty"`
	DenyCIDRs           []string        `json:"denyCIDRs,omitempty"`
	TrustProxy          bool            `json:"trustProxy,omitempty"`
	TrustedProxyCIDRs   []string        `json:"trustedProxyCIDRs,omitempty"`
	BanEscalationConfig *struct {
		TempThreshold int    `json:"tempThreshold"`
		Window        string `json:"window"`
	} `json:"banEscalation,omitempty"`
}

type EndpointRules struct {
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	RateLimit RateLimit `json:"rateLimit"`
	Actions   []Action  `json:"actions"`
}

type Threshold struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
}

type RateLimit struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
	Burst             int `json:"burst,omitempty"`
}

type Action struct {
	Type          string   `json:"type"`
	Priority      int      `json:"priority,omitempty"` // Higher values = higher priority
	Limit         string   `json:"limit,omitempty"`
	Duration      string   `json:"duration,omitempty"`
	JitterRangeMs []int    `json:"jitterRangeMs,omitempty"`
	Trigger       *Trigger `json:"trigger,omitempty"`
	Response      Response `json:"response"`
}

type PipelineNode struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function string         `json:"function"`
	Params   map[string]any `json:"params,omitempty"`
}

type PipelineEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Pipeline struct {
	Nodes       []PipelineNode `json:"nodes"`
	Edges       []PipelineEdge `json:"edges"`
	Combination string         `json:"combination,omitempty"` // "AND" or "OR", defaults to "OR"
}

type Rule struct {
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Enabled       bool           `json:"enabled"`
	Priority      int            `json:"priority,omitempty"` // Higher values = higher priority
	Params        map[string]any `json:"params"`
	Pipeline      *Pipeline      `json:"pipeline,omitempty"`
	Actions       []Action       `json:"actions"`
	sortedActions []Action       // Cached sorted actions for performance
}

type Context struct {
	RuleEngine *RuleEngine
	FiberCtx   *fiber.Ctx
	Results    map[string]any
	Triggered  bool
}

type Trigger map[string]any

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type RuleEngine struct {
	config         *AnomalyConfig
	configDir      string
	Store          CounterStore
	rateLimiter    RateLimiter
	actionRegistry *ActionHandlerRegistry
	pipelineReg    PipelineFunctionRegistry
	metrics        MetricsCollector
	validator      ConfigValidator
	sortedRules    []Rule // Cached sorted rules for performance
	rulesMutex     sync.RWMutex
	watcher        *fsnotify.Watcher
	watcherMutex   sync.Mutex
	// compiled access lists
	allowNets           []*net.IPNet
	denyNets            []*net.IPNet
	trustedProxyNets    []*net.IPNet
	trustProxy          bool
	banEscalationWindow time.Duration
	banEscalationThresh int
}

// DefaultConfigValidator implements ConfigValidator
// DefaultConfigValidator implements ConfigValidator
type DefaultConfigValidator struct{}

// SimpleLogger implements Logger with basic structured logging
type SimpleLogger struct{}

func NewSimpleLogger() *SimpleLogger {
	return &SimpleLogger{}
}

func (l *SimpleLogger) Debug(msg string, fields map[string]any) {
	l.log("DEBUG", msg, fields)
}

func (l *SimpleLogger) Info(msg string, fields map[string]any) {
	l.log("INFO", msg, fields)
}

func (l *SimpleLogger) Warn(msg string, fields map[string]any) {
	l.log("WARN", msg, fields)
}

func (l *SimpleLogger) Error(msg string, fields map[string]any) {
	l.log("ERROR", msg, fields)
}

func (l *SimpleLogger) log(level, msg string, fields map[string]any) {
	// Simple implementation - in production, use a proper structured logger
	fmt.Printf("[%s] %s", level, msg)
	if len(fields) > 0 {
		fmt.Printf(" | ")
		first := true
		for k, v := range fields {
			if !first {
				fmt.Printf(", ")
			}
			fmt.Printf("%s=%v", k, v)
			first = false
		}
	}
	fmt.Println()
}

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
	// Simple label key generation - in production, sort keys for consistency
	var parts []string
	for k, v := range labels {
		parts = append(parts, k+"="+v)
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

func NewDefaultConfigValidator() *DefaultConfigValidator {
	return &DefaultConfigValidator{}
}

func (v *DefaultConfigValidator) Validate(config *AnomalyConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	if config.AnomalyDetectionRules.Global.Rules == nil {
		config.AnomalyDetectionRules.Global.Rules = make(map[string]Rule)
	}

	// Validate global rules
	for name, rule := range config.AnomalyDetectionRules.Global.Rules {
		if err := v.validateRule(name, &rule); err != nil {
			return fmt.Errorf("invalid global rule %s: %v", name, err)
		}
	}

	// Validate endpoint rules
	for endpoint, endpointRule := range config.AnomalyDetectionRules.APIEndpoints {
		if endpoint == "" {
			return fmt.Errorf("endpoint rule has empty endpoint")
		}
		if endpointRule.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("endpoint %s has invalid rate limit: %d", endpoint, endpointRule.RateLimit.RequestsPerMinute)
		}
		for i, action := range endpointRule.Actions {
			if err := v.validateAction(fmt.Sprintf("endpoint %s action %d", endpoint, i), &action); err != nil {
				return err
			}
		}
	}

	return nil
}

func (v *DefaultConfigValidator) validateRule(name string, rule *Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule has empty name")
	}
	if rule.Type == "" {
		return fmt.Errorf("rule %s has empty type", name)
	}
	for i, action := range rule.Actions {
		if err := v.validateAction(fmt.Sprintf("rule %s action %d", name, i), &action); err != nil {
			return err
		}
	}
	return nil
}

func (v *DefaultConfigValidator) validateAction(context string, action *Action) error {
	if action.Type == "" {
		return fmt.Errorf("%s has empty type", context)
	}
	validTypes := []string{"rate_limit", "temporary_ban", "permanent_ban", "jitter_warning"}
	valid := false
	for _, t := range validTypes {
		if action.Type == t {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("%s has invalid type: %s", context, action.Type)
	}
	if action.Response.Status < 100 || action.Response.Status > 599 {
		return fmt.Errorf("%s has invalid status code: %d", context, action.Response.Status)
	}
	return nil
}

func NewRuleEngine(configDir string, store CounterStore, rateLimiter RateLimiter, actionRegistry *ActionHandlerRegistry, pipelineReg PipelineFunctionRegistry, metrics MetricsCollector, validator ConfigValidator) (*RuleEngine, error) {
	config, err := loadConfig(configDir)
	if err != nil {
		return nil, err
	}

	// Validate configuration
	if validator != nil {
		if err := validator.Validate(config); err != nil {
			return nil, fmt.Errorf("config validation failed: %v", err)
		}
	}

	ruleEngine := &RuleEngine{
		config:         config,
		configDir:      configDir,
		Store:          store,
		rateLimiter:    rateLimiter,
		actionRegistry: actionRegistry,
		pipelineReg:    pipelineReg,
		metrics:        metrics,
		validator:      validator,
	}

	ruleEngine.updateSortedRules()
	ruleEngine.applyConfigDerived()
	ruleEngine.startCleanupRoutine()

	// Setup file watcher for hot reload
	if err := ruleEngine.setupFileWatcher(); err != nil {
		// Log warning but don't fail initialization
		fmt.Printf("Warning: failed to setup config file watcher: %v\n", err)
	}

	return ruleEngine, nil
}

func (re *RuleEngine) updateSortedRules() {
	re.rulesMutex.Lock()
	defer re.rulesMutex.Unlock()

	rules := make([]Rule, 0, len(re.config.AnomalyDetectionRules.Global.Rules))
	for _, rule := range re.config.AnomalyDetectionRules.Global.Rules {
		rule.sortedActions = re.sortActions(rule.Actions)
		rules = append(rules, rule)
	}

	// Sort rules by priority (higher priority first)
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Priority < rules[j].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	re.sortedRules = rules
}

// applyConfigDerived compiles CIDR lists and sets derived settings
func (re *RuleEngine) applyConfigDerived() {
	gr := re.config.AnomalyDetectionRules.Global
	re.allowNets = parseCIDRs(gr.AllowCIDRs)
	re.denyNets = parseCIDRs(gr.DenyCIDRs)
	re.trustedProxyNets = parseCIDRs(gr.TrustedProxyCIDRs)
	re.trustProxy = gr.TrustProxy
	// Ban escalation defaults
	re.banEscalationThresh = 3
	re.banEscalationWindow = 24 * time.Hour
	if gr.BanEscalationConfig != nil {
		if gr.BanEscalationConfig.TempThreshold > 0 {
			re.banEscalationThresh = gr.BanEscalationConfig.TempThreshold
		}
		if gr.BanEscalationConfig.Window != "" {
			if d, err := time.ParseDuration(gr.BanEscalationConfig.Window); err == nil {
				re.banEscalationWindow = d
			}
		}
	}
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		if strings.TrimSpace(c) == "" {
			continue
		}
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && n != nil {
			nets = append(nets, n)
			continue
		}
		// Support single IPs
		ip := net.ParseIP(strings.TrimSpace(c))
		if ip != nil {
			mask := net.CIDRMask(len(ip)*8, len(ip)*8)
			nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return nets
}

func ipInNets(ipStr string, nets []*net.IPNet) bool {
	if ipStr == "" {
		return false
	}
	addr := net.ParseIP(ipStr)
	if addr == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func (re *RuleEngine) sortActions(actions []Action) []Action {
	if len(actions) <= 1 {
		return actions
	}

	sorted := make([]Action, len(actions))
	copy(sorted, actions)

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			// Compare by priority first
			if sorted[i].Priority < sorted[j].Priority {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			} else if sorted[i].Priority == sorted[j].Priority {
				// If same priority, prefer ban actions over rate_limit
				if sorted[i].Type == "rate_limit" && (sorted[j].Type == "temporary_ban" || sorted[j].Type == "permanent_ban") {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
	}

	return sorted
}

func (re *RuleEngine) getSortedRules() []Rule {
	re.rulesMutex.RLock()
	defer re.rulesMutex.RUnlock()
	return re.sortedRules
}

func loadConfig(configDir string) (*AnomalyConfig, error) {
	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				Rules: make(map[string]Rule),
			},
			APIEndpoints: make(map[string]EndpointRules),
		},
	}

	// Load global rules
	if err := loadGlobalRules(configDir+"/global", config); err != nil {
		return nil, fmt.Errorf("failed to load global rules: %v", err)
	}

	// Load pipeline rules
	if err := loadPipelineRules(configDir+"/rules", config); err != nil {
		return nil, fmt.Errorf("failed to load pipeline rules: %v", err)
	}

	// Load endpoint rules
	if err := loadEndpointRules(configDir+"/endpoints", config); err != nil {
		return nil, fmt.Errorf("failed to load endpoint rules: %v", err)
	}

	return config, nil
}

func loadGlobalRules(globalDir string, config *AnomalyConfig) error {
	files, err := os.ReadDir(globalDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to read global rules directory: %v", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		// Validate file name to prevent directory traversal
		if strings.Contains(file.Name(), "..") || strings.Contains(file.Name(), "/") {
			return fmt.Errorf("invalid file name: %s", file.Name())
		}

		filePath := globalDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read global rule file %s: %v", file.Name(), err)
		}

		// Limit file size to prevent memory exhaustion
		if len(data) > 1024*1024 { // 1MB limit
			return fmt.Errorf("config file %s is too large", file.Name())
		}

		// Probe JSON to decide how to handle: rule or global overlay
		var probe map[string]any
		if err := json.Unmarshal(data, &probe); err != nil {
			return fmt.Errorf("failed to parse global file %s: %v", file.Name(), err)
		}
		nameVal, hasName := probe["name"].(string)
		if hasName && strings.TrimSpace(nameVal) != "" {
			// This is a Rule
			var rule Rule
			if err := json.Unmarshal(data, &rule); err != nil {
				return fmt.Errorf("failed to parse global rule file %s: %v", file.Name(), err)
			}
			if config.AnomalyDetectionRules.Global.Rules == nil {
				config.AnomalyDetectionRules.Global.Rules = make(map[string]Rule)
			}
			config.AnomalyDetectionRules.Global.Rules[rule.Name] = rule
			continue
		}
		// Otherwise, treat as a global overlay/config
		type globalOverlay struct {
			AllowCIDRs        []string `json:"allowCIDRs"`
			DenyCIDRs         []string `json:"denyCIDRs"`
			TrustProxy        bool     `json:"trustProxy"`
			TrustedProxyCIDRs []string `json:"trustedProxyCIDRs"`
			BanEscalation     *struct {
				TempThreshold int    `json:"tempThreshold"`
				Window        string `json:"window"`
			} `json:"banEscalation"`
		}
		var overlay globalOverlay
		if err := json.Unmarshal(data, &overlay); err != nil {
			return fmt.Errorf("failed to parse global overlay file %s: %v", file.Name(), err)
		}
		gr := &config.AnomalyDetectionRules.Global
		if len(overlay.AllowCIDRs) > 0 {
			gr.AllowCIDRs = overlay.AllowCIDRs
		}
		if len(overlay.DenyCIDRs) > 0 {
			gr.DenyCIDRs = overlay.DenyCIDRs
		}
		// TrustProxy is a boolean; we set it if the key existed or true. Since we can't easily detect presence, honor value directly.
		gr.TrustProxy = gr.TrustProxy || overlay.TrustProxy
		if len(overlay.TrustedProxyCIDRs) > 0 {
			gr.TrustedProxyCIDRs = overlay.TrustedProxyCIDRs
		}
		if overlay.BanEscalation != nil {
			gr.BanEscalationConfig = &struct {
				TempThreshold int    `json:"tempThreshold"`
				Window        string `json:"window"`
			}{
				TempThreshold: overlay.BanEscalation.TempThreshold,
				Window:        overlay.BanEscalation.Window,
			}
		}
	}

	return nil
}

func loadPipelineRules(rulesDir string, config *AnomalyConfig) error {
	files, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to read rules directory: %v", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		filePath := rulesDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read rule file %s: %v", file.Name(), err)
		}

		var rule Rule
		if err := json.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("failed to parse rule file %s: %v", file.Name(), err)
		}

		config.AnomalyDetectionRules.Global.Rules[rule.Name] = rule
	}

	return nil
}

func loadEndpointRules(endpointsDir string, config *AnomalyConfig) error {
	files, err := os.ReadDir(endpointsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to read endpoints directory: %v", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		filePath := endpointsDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read endpoint file %s: %v", file.Name(), err)
		}

		var endpoint EndpointRules
		if err := json.Unmarshal(data, &endpoint); err != nil {
			return fmt.Errorf("failed to parse endpoint file %s: %v", file.Name(), err)
		}

		config.AnomalyDetectionRules.APIEndpoints[endpoint.Endpoint] = endpoint
	}

	return nil
}

func (re *RuleEngine) GetClientIP(c *fiber.Ctx) string {
	// Determine remote address without trusting headers by default
	remoteIP := c.Context().RemoteIP().String()
	candidate := remoteIP
	if re.trustProxy && ipInNets(remoteIP, re.trustedProxyNets) {
		// Trust first IP in X-Forwarded-For chain as the client IP
		xff := c.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				first := strings.TrimSpace(parts[0])
				if first != "" {
					candidate = first
				}
			}
		}
	}
	// Fallback to library if needed
	if candidate == "" || candidate == "unknown" {
		candidate = ip.FromRequest(c)
	}
	// Validate IP address
	if candidate == "" || candidate == "unknown" {
		return ""
	}
	// Basic IP validation
	if len(candidate) > 45 { // IPv6 max length
		return ""
	}
	return candidate
}

func (re *RuleEngine) GetUserID(c *fiber.Ctx) string {
	return c.Get("X-User-ID")
}

func (re *RuleEngine) GetCountryFromIP(ipAddr string, defaultCountry string) string {
	return re.getCountryFromIPService(ipAddr, defaultCountry)
}

func (re *RuleEngine) getCountryFromIPService(ipAddr string, defaultCountry string) string {
	// Rate limit geolocation requests to prevent abuse
	// In production, you might want to cache results or use a local database

	// For demo purposes, return default or implement a simple mapping
	if ipAddr == "" {
		return defaultCountry
	}

	// Simple IP to country mapping for common cases
	switch {
	case strings.HasPrefix(ipAddr, "192.168."):
		return "LOCAL"
	case strings.HasPrefix(ipAddr, "10."):
		return "LOCAL"
	case strings.HasPrefix(ipAddr, "172."):
		return "LOCAL"
	default:
		// Use external service with timeout and error handling
		return re.callGeolocationAPI(ipAddr, defaultCountry)
	}
}

func (re *RuleEngine) callGeolocationAPI(ipAddr string, defaultCountry string) string {
	country := ip.Country(ipAddr)
	if country != "" {
		return country
	}
	return defaultCountry
}

func (re *RuleEngine) checkEndpointRateLimit(c *fiber.Ctx, clientIP, endpoint string) *Action {
	rules, exists := re.config.AnomalyDetectionRules.APIEndpoints[endpoint]
	if !exists {
		return nil
	}
	counter, err := re.Store.IncrementEndpoint(clientIP, endpoint)
	if err != nil {
		return nil
	}
	now := time.Now()
	if now.Sub(counter.LastReset) > time.Minute {
		// Reset burst
		counter.Burst = 0
	}
	if rules.RateLimit.Burst > 0 && counter.Burst > rules.RateLimit.Burst {
		for _, action := range rules.Actions {
			if action.Type == "jitter_warning" {
				if re.isActionTriggered(c, clientIP, endpoint, action) {
					return &action
				}
			}
		}
	}
	if counter.Count > rules.RateLimit.RequestsPerMinute {
		for _, action := range rules.Actions {
			if action.Type == "rate_limit" {
				if re.isActionTriggered(c, clientIP, endpoint, action) {
					return &action
				}
			}
		}
		if a := re.evaluateTriggers(c, clientIP, endpoint, rules.Actions); a != nil {
			return a
		}
	}
	return nil
}

func (re *RuleEngine) isActionTriggered(c *fiber.Ctx, clientIP, endpoint string, action Action) bool {
	if action.Trigger == nil {
		return true
	}
	trigger := *action.Trigger
	thresholdVal, ok := trigger["threshold"].(float64)
	if !ok {
		return false
	}
	threshold := int(thresholdVal)
	if threshold <= 0 {
		return false
	}
	var window time.Duration
	if within, ok := trigger["within"].(string); ok && within != "" {
		if d, err := time.ParseDuration(within); err == nil {
			window = d
		}
	}
	scope, ok := trigger["scope"].(string)
	if !ok || scope == "" {
		scope = "client_endpoint"
	}
	counterType, ok := trigger["key"].(string)
	if !ok {
		counterType = "default"
	}
	method := ""
	if c != nil {
		method = c.Method()
	}
	key := re.makeTriggerKey(scope, clientIP, endpoint, method, 0) + "|" + counterType
	count, first, err := re.Store.IncrementActionCounter(key, window)
	if err != nil {
		return false
	}
	if window == 0 {
		return count >= threshold
	} else if time.Since(first) <= window && count >= threshold {
		return true
	}
	return false
}

func (re *RuleEngine) evaluateTriggers(c *fiber.Ctx, clientIP, endpoint string, actions []Action) *Action {
	now := time.Now()
	for idx, action := range actions {
		if action.Trigger == nil {
			continue
		}
		trigger := *action.Trigger
		thresholdVal, ok := trigger["threshold"].(float64)
		if !ok {
			continue
		}
		threshold := int(thresholdVal)
		if threshold <= 0 {
			continue
		}
		var window time.Duration
		if within, ok := trigger["within"].(string); ok && within != "" {
			if d, err := time.ParseDuration(within); err == nil {
				window = d
			}
		}
		scope, ok := trigger["scope"].(string)
		if !ok || scope == "" {
			scope = "client_endpoint"
		}
		counterType, ok := trigger["key"].(string)
		if !ok {
			counterType = "default"
		}
		key := re.makeTriggerKey(scope, clientIP, endpoint, c.Method(), idx) + "|" + counterType
		count, first, err := re.Store.IncrementActionCounter(key, window)
		if err != nil {
			continue
		}
		if window == 0 {
			if count >= threshold {
				return &action
			}
		} else if now.Sub(first) <= window && count >= threshold {
			return &action
		}
	}
	return nil
}

func (re *RuleEngine) makeTriggerKey(scope, clientIP, endpoint, method string, actionIdx int) string {
	switch scope {
	case "client":
		return fmt.Sprintf("client|%s|action|%d", clientIP, actionIdx)
	case "client_endpoint_method":
		return fmt.Sprintf("client|%s|endpoint|%s|method|%s|action|%d", clientIP, endpoint, method, actionIdx)
	default:
		return fmt.Sprintf("client|%s|endpoint|%s|action|%d", clientIP, endpoint, actionIdx)
	}
}

func (re *RuleEngine) applyAction(c *fiber.Ctx, action *Action, clientIP string) error {
	if re.actionRegistry != nil {
		if handler, exists := re.actionRegistry.Get(action.Type); exists {
			meta := ActionMeta{
				ClientIP: clientIP,
				Endpoint: c.Path(),
				UserID:   re.GetUserID(c),
			}
			return handler.Handle(context.Background(), c, *action, meta, re.Store)
		}
	}
	// Fallback to built-in handlers
	switch action.Type {
	case "jitter_warning":
		return re.applyJitterWarning(c, action)
	case "rate_limit":
		return re.applyRateLimit(c, action)
	case "temporary_ban":
		return re.applyTemporaryBan(c, action, clientIP)
	case "permanent_ban":
		return re.applyPermanentBan(c, action, clientIP)
	}
	return nil
}

func (re *RuleEngine) applyActionSideEffects(c *fiber.Ctx, action *Action, clientIP string) error {
	// Apply action side effects without setting response
	switch action.Type {
	case "temporary_ban", "permanent_ban":
		// Set the ban but don't return response yet
		duration, err := time.ParseDuration(action.Duration)
		if err != nil {
			duration = 10 * time.Minute
		}
		ban := &BanInfo{
			Until:      time.Now().Add(duration),
			Permanent:  action.Type == "permanent_ban",
			Reason:     action.Response.Message,
			StatusCode: action.Response.Status,
		}
		if err := re.Store.SetBan(clientIP, ban); err != nil {
			return fmt.Errorf("failed to set ban for %s: %v", clientIP, err)
		}
		// Escalate to permanent ban if too many temp bans in window
		if action.Type == "temporary_ban" && re.banEscalationThresh > 0 {
			key := "tempban|client|" + clientIP
			count, _, _ := re.Store.IncrementActionCounter(key, re.banEscalationWindow)
			if count >= re.banEscalationThresh {
				permban := &BanInfo{Permanent: true, Reason: "escalated temporary bans", StatusCode: action.Response.Status}
				_ = re.Store.SetBan(clientIP, permban)
			}
		}
		return nil
	case "rate_limit":
		// For rate limit, we still need to set headers but not the JSON response
		c.Set("X-RateLimit-Remaining", "0")
		if action.Duration != "" {
			if d, err := time.ParseDuration(action.Duration); err == nil {
				c.Set("Retry-After", fmt.Sprintf("%.0f", d.Seconds()))
			}
		}
		return nil
	default:
		// For other actions, apply normally
		return re.applyAction(c, action, clientIP)
	}
}

func (re *RuleEngine) applyActionResponse(c *fiber.Ctx, action *Action, clientIP string) error {
	// Apply only the response part of the action
	switch action.Type {
	case "temporary_ban":
		duration, err := time.ParseDuration(action.Duration)
		if err != nil {
			duration = 10 * time.Minute
		}
		return c.Status(action.Response.Status).JSON(fiber.Map{
			"error":        action.Response.Message,
			"type":         "temporary_ban",
			"duration":     duration.String(),
			"banned_until": time.Now().Add(duration).Format(time.RFC3339),
		})
	case "permanent_ban":
		return c.Status(action.Response.Status).JSON(fiber.Map{
			"error": action.Response.Message,
			"type":  "permanent_ban",
		})
	case "rate_limit":
		return c.Status(action.Response.Status).JSON(fiber.Map{
			"error": action.Response.Message,
			"type":  "rate_limit",
		})
	default:
		// For other actions, apply normally
		return re.applyAction(c, action, clientIP)
	}
}

func (re *RuleEngine) applyJitterWarning(c *fiber.Ctx, action *Action) error {
	// Instead of blocking sleep, return retry-after
	jitter := 1000 // ms
	if len(action.JitterRangeMs) == 2 {
		minVal := action.JitterRangeMs[0]
		maxVal := action.JitterRangeMs[1]
		jitter = rand.Intn(maxVal-minVal) + minVal
	}
	c.Set("Retry-After", fmt.Sprintf("%.3f", float64(jitter)/1000))
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "jitter_warning",
	})
}

func (re *RuleEngine) applyRateLimit(c *fiber.Ctx, action *Action) error {
	c.Set("X-RateLimit-Remaining", "0")
	if action.Duration != "" {
		if d, err := time.ParseDuration(action.Duration); err == nil {
			c.Set("Retry-After", fmt.Sprintf("%.0f", d.Seconds()))
		}
	}
	// Return the rate limit response
	status := action.Response.Status
	if status == 0 {
		status = 429
	}
	return c.Status(status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "rate_limit",
	})
}

func (re *RuleEngine) applyTemporaryBan(c *fiber.Ctx, action *Action, clientIP string) error {
	duration, err := time.ParseDuration(action.Duration)
	if err != nil {
		duration = 10 * time.Minute
	}
	ban := &BanInfo{
		Until:      time.Now().Add(duration),
		Permanent:  false,
		Reason:     action.Response.Message,
		StatusCode: action.Response.Status,
	}
	err = re.Store.SetBan(clientIP, ban)
	if err != nil {
		return err
	}
	// Escalate if threshold reached
	if re.banEscalationThresh > 0 {
		key := "tempban|client|" + clientIP
		count, _, _ := re.Store.IncrementActionCounter(key, re.banEscalationWindow)
		if count >= re.banEscalationThresh {
			permban := &BanInfo{Permanent: true, Reason: "escalated temporary bans", StatusCode: action.Response.Status}
			_ = re.Store.SetBan(clientIP, permban)
			status := action.Response.Status
			if status == 0 {
				status = 403
			}
			return c.Status(status).JSON(fiber.Map{
				"error": "escalated temporary bans",
				"type":  "permanent_ban",
			})
		}
	}
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error":        action.Response.Message,
		"type":         "temporary_ban",
		"duration":     duration.String(),
		"banned_until": time.Now().Add(duration).Format(time.RFC3339),
	})
}

func (re *RuleEngine) applyPermanentBan(c *fiber.Ctx, action *Action, clientIP string) error {
	ban := &BanInfo{
		Until:      time.Time{},
		Permanent:  true,
		Reason:     action.Response.Message,
		StatusCode: action.Response.Status,
	}
	err := re.Store.SetBan(clientIP, ban)
	if err != nil {
		return err
	}
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "permanent_ban",
	})
}

func (re *RuleEngine) isBanned(clientIP string) *BanInfo {
	banInfo, err := re.Store.GetBan(clientIP)
	if err != nil || banInfo == nil {
		return nil
	}
	if banInfo.Permanent {
		return banInfo
	}
	if time.Now().Before(banInfo.Until) {
		return banInfo
	}
	re.Store.DeleteBan(clientIP)
	return nil
}

func (re *RuleEngine) AnomalyDetectionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientIP := re.GetClientIP(c)
		endpoint := c.Path()

		// Enforce deny/allow lists early
		if ipInNets(clientIP, re.denyNets) {
			return c.Status(403).JSON(fiber.Map{"error": "access denied", "type": "deny_list"})
		}
		if len(re.allowNets) > 0 && !ipInNets(clientIP, re.allowNets) {
			// If allow list is defined, only allow those; others denied
			return c.Status(403).JSON(fiber.Map{"error": "access restricted", "type": "allow_list"})
		}

		if banInfo := re.isBanned(clientIP); banInfo != nil {
			status := banInfo.StatusCode
			if status == 0 {
				status = 403
			}
			message := banInfo.Reason
			if banInfo.Permanent {
				return c.Status(status).JSON(fiber.Map{
					"error": message,
					"type":  "permanent_ban",
				})
			} else {
				return c.Status(status).JSON(fiber.Map{
					"error":        message,
					"type":         "temporary_ban",
					"banned_until": banInfo.Until.Format(time.RFC3339),
				})
			}
		}

		// Check all global rules (sorted by priority, highest first)
		rules := re.getSortedRules()

		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			triggered := false
			if rule.Pipeline != nil {
				triggered = re.executePipeline(c, rule.Pipeline, rule.Params)
			} else {
				handler, exists := re.pipelineReg.Get(rule.Type)
				if exists {
					ctx := &Context{
						RuleEngine: re,
						FiberCtx:   c,
						Results:    make(map[string]any),
						Triggered:  false,
					}
					for k, v := range rule.Params {
						ctx.Results[k] = v
					}
					result := handler(ctx)
					if t, ok := result.(bool); ok {
						triggered = t
					}
				}
			}
			if triggered {
				var mostSevereAction *Action

				// Use pre-sorted actions
				actions := rule.sortedActions

				// Find the highest priority triggered action
				for _, a := range actions {
					if re.isActionTriggered(c, clientIP, "", a) {
						mostSevereAction = &a
						break
					}
				}

				// Second pass: apply all actions for side effects only
				for _, a := range actions {
					if re.isActionTriggered(c, clientIP, "", a) {
						if err := re.applyActionSideEffects(c, &a, clientIP); err != nil {
							return err
						}
					}
				}

				// Apply the response from the most severe action
				if mostSevereAction != nil {
					return re.applyActionResponse(c, mostSevereAction, clientIP)
				}

				// Return early after applying actions for triggered global rule
				return nil
			}
		}
		if action := re.checkEndpointRateLimit(c, clientIP, endpoint); action != nil {
			return re.applyAction(c, action, clientIP)
		}
		return c.Next()
	}
}

func (re *RuleEngine) startCleanupRoutine() {
	// Cleanup is handled by store TTL or in-memory expiration
}

func (re *RuleEngine) executePipeline(c *fiber.Ctx, pipeline *Pipeline, ruleParams map[string]any) bool {
	if pipeline == nil {
		return false
	}
	ctx := &Context{
		RuleEngine: re,
		FiberCtx:   c,
		Results:    make(map[string]any),
		Triggered:  false,
	}
	for k, v := range ruleParams {
		ctx.Results[k] = v
	}

	// Track condition results for combination logic
	conditionResults := make([]bool, 0)
	combination := pipeline.Combination
	if combination == "" {
		combination = "OR" // Default to OR for backward compatibility
	}

	// Execute all nodes in topological order
	adjList := make(map[string][]string)
	inDegree := make(map[string]int)
	nodeMap := make(map[string]PipelineNode)
	for _, node := range pipeline.Nodes {
		nodeMap[node.ID] = node
		inDegree[node.ID] = 0
	}
	for _, edge := range pipeline.Edges {
		// Validate that nodes exist
		if _, exists := nodeMap[edge.From]; !exists {
			fmt.Printf("Warning: edge from non-existent node %s\n", edge.From)
			continue
		}
		if _, exists := nodeMap[edge.To]; !exists {
			fmt.Printf("Warning: edge to non-existent node %s\n", edge.To)
			continue
		}
		adjList[edge.From] = append(adjList[edge.From], edge.To)
		inDegree[edge.To]++
	}
	var queue []string
	for nodeID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, nodeID)
		}
	}

	// Execute all nodes in topological order and collect condition results
	executed := make(map[string]bool)
	processedCount := 0

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		if executed[currentID] {
			continue
		}
		node := nodeMap[currentID]
		if node.Type == "utility" || node.Type == "condition" {
			for k, v := range node.Params {
				ctx.Results[k] = v
			}
			if fn, exists := re.pipelineReg.Get(node.Function); exists {
				result := fn(ctx)
				ctx.Results[node.ID] = result
				if node.Type == "condition" {
					if triggered, ok := result.(bool); ok {
						conditionResults = append(conditionResults, triggered)
					}
				}
			} else {
				// Log missing function for debugging
				fmt.Printf("Warning: pipeline function %s not found\n", node.Function)
			}
		}
		executed[currentID] = true
		processedCount++

		for _, neighbor := range adjList[currentID] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	// Check for cycles or unprocessed nodes
	if processedCount < len(pipeline.Nodes) {
		fmt.Printf("Warning: pipeline has cycles or unprocessed nodes (%d/%d processed)\n", processedCount, len(pipeline.Nodes))
	}

	// Apply combination logic to ALL conditions collected from ALL branches
	if len(conditionResults) == 0 {
		return false
	}

	if combination == "AND" {
		// All conditions must be true
		for _, result := range conditionResults {
			if !result {
				return false
			}
		}
		return true
	} else {
		// OR logic (default): Any condition must be true
		for _, result := range conditionResults {
			if result {
				return true
			}
		}
		return false
	}
}

// HealthCheck performs a health check on the rule engine
func (re *RuleEngine) HealthCheck() error {
	// Check if config is loaded
	if re.config == nil {
		return fmt.Errorf("rule engine config is not loaded")
	}

	// Check if store is accessible
	if re.Store == nil {
		return fmt.Errorf("rule engine store is not initialized")
	}

	// Check if rate limiter is accessible
	if re.rateLimiter == nil {
		return fmt.Errorf("rule engine rate limiter is not initialized")
	}

	// Check if metrics collector is accessible
	if re.metrics == nil {
		return fmt.Errorf("rule engine metrics collector is not initialized")
	}

	// Check if pipeline registry is accessible
	if re.pipelineReg == nil {
		return fmt.Errorf("rule engine pipeline registry is not initialized")
	}

	// Check if action registry is accessible
	if re.actionRegistry == nil {
		return fmt.Errorf("rule engine action registry is not initialized")
	}

	// Try to access sorted rules (this will check if rules are properly loaded)
	re.rulesMutex.RLock()
	rulesCount := len(re.sortedRules)
	re.rulesMutex.RUnlock()

	if rulesCount == 0 {
		return fmt.Errorf("no rules are loaded in the rule engine")
	}

	return nil
}

// setupFileWatcher sets up file system watcher for config hot reload
func (re *RuleEngine) setupFileWatcher() error {
	re.watcherMutex.Lock()
	defer re.watcherMutex.Unlock()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}

	re.watcher = watcher

	// Watch the main config directory
	if err := re.watcher.Add(re.configDir); err != nil {
		re.watcher.Close()
		return fmt.Errorf("failed to watch config directory %s: %v", re.configDir, err)
	}

	// Watch subdirectories
	subdirs := []string{"/global", "/rules", "/endpoints"}
	for _, subdir := range subdirs {
		fullPath := re.configDir + subdir
		if _, err := os.Stat(fullPath); err == nil {
			if err := re.watcher.Add(fullPath); err != nil {
				fmt.Printf("Warning: failed to watch config subdirectory %s: %v\n", fullPath, err)
			}
		}
	}

	// Start watching in a goroutine
	go re.watchConfigChanges()

	return nil
}

// watchConfigChanges monitors config file changes and triggers reload
func (re *RuleEngine) watchConfigChanges() {
	for {
		select {
		case event, ok := <-re.watcher.Events:
			if !ok {
				return
			}

			// Only reload on write events for JSON files
			if event.Has(fsnotify.Write) && strings.HasSuffix(event.Name, ".json") {
				fmt.Printf("Config file changed: %s, reloading...\n", event.Name)
				if err := re.ReloadConfig(); err != nil {
					fmt.Printf("Error reloading config: %v\n", err)
				} else {
					fmt.Printf("Config reloaded successfully\n")
				}
			}

		case err, ok := <-re.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("Config file watcher error: %v\n", err)
		}
	}
}

// ReloadConfig reloads the configuration from disk
func (re *RuleEngine) ReloadConfig() error {
	re.watcherMutex.Lock()
	defer re.watcherMutex.Unlock()

	// Load new config
	newConfig, err := loadConfig(re.configDir)
	if err != nil {
		return fmt.Errorf("failed to load new config: %v", err)
	}

	// Validate new config
	if re.validator != nil {
		if err := re.validator.Validate(newConfig); err != nil {
			return fmt.Errorf("new config validation failed: %v", err)
		}
	}

	// Update config and rules atomically
	re.config = newConfig
	re.updateSortedRules()
	re.applyConfigDerived()

	// Log successful reload
	if re.metrics != nil {
		re.metrics.IncrementCounter("config_reload_success", map[string]string{
			"config_dir": re.configDir,
		})
	}

	return nil
}

// StopWatcher stops the file watcher (call this during shutdown)
func (re *RuleEngine) StopWatcher() error {
	re.watcherMutex.Lock()
	defer re.watcherMutex.Unlock()

	if re.watcher != nil {
		return re.watcher.Close()
	}
	return nil
}
