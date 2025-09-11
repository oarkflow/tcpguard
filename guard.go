package tcpguard

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

type AnomalyConfig struct {
	AnomalyDetectionRules AnomalyDetectionRules `json:"anomalyDetectionRules"`
}

type AnomalyDetectionRules struct {
	Global       GlobalRules              `json:"global"`
	APIEndpoints map[string]EndpointRules `json:"apiEndpoints"`
}

type GlobalRules struct {
	DDOSDetection DDOSDetection   `json:"ddosDetection"`
	MITMDetection MITMDetection   `json:"mitmDetection"`
	Rules         map[string]Rule `json:"rules"`
}

type DDOSDetection struct {
	Enabled   bool      `json:"enabled"`
	Threshold Threshold `json:"threshold"`
	Actions   []Action  `json:"actions"`
}

type MITMDetection struct {
	Enabled              bool     `json:"enabled"`
	Indicators           []string `json:"indicators"`
	Actions              []Action `json:"actions"`
	SuspiciousUserAgents []string `json:"suspiciousUserAgents,omitempty"`
}

type EndpointRules struct {
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
	Limit         string   `json:"limit,omitempty"`
	Duration      string   `json:"duration,omitempty"`
	JitterRangeMs []int    `json:"jitterRangeMs,omitempty"`
	Trigger       *Trigger `json:"trigger,omitempty"`
	Response      Response `json:"response"`
}

type Rule struct {
	Type    string                 `json:"type"`
	Enabled bool                   `json:"enabled"`
	Params  map[string]interface{} `json:"params"`
	Actions []Action               `json:"actions"`
}

type Trigger map[string]interface{}

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type ClientTracker struct {
	mu               sync.RWMutex
	globalRequests   map[string]*RequestCounter
	endpointRequests map[string]map[string]*RequestCounter
	bannedClients    map[string]*BanInfo
	actionCounters   map[string]map[string]*GenericCounter
	userSessions     map[string][]*SessionInfo
}

type RequestCounter struct {
	Count     int
	LastReset time.Time
	Burst     int
}

type BanInfo struct {
	Until      time.Time
	Permanent  bool
	Reason     string
	StatusCode int
}

type GenericCounter struct {
	Count int
	First time.Time
}

type SessionInfo struct {
	UA      string
	Created time.Time
}

type RuleEngine struct {
	config  *AnomalyConfig
	tracker *ClientTracker
}

func NewRuleEngine(configPath string) (*RuleEngine, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	tracker := &ClientTracker{
		globalRequests:   make(map[string]*RequestCounter),
		endpointRequests: make(map[string]map[string]*RequestCounter),
		bannedClients:    make(map[string]*BanInfo),
		actionCounters:   make(map[string]map[string]*GenericCounter),
		userSessions:     make(map[string][]*SessionInfo),
	}
	ruleEngine := &RuleEngine{
		config:  config,
		tracker: tracker,
	}
	ruleEngine.startCleanupRoutine()
	return ruleEngine, nil
}

func loadConfig(configPath string) (*AnomalyConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var config AnomalyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}
	return &config, nil
}

func (re *RuleEngine) getClientIP(c *fiber.Ctx) string {
	if ip := c.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := c.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return c.IP()
}

func (re *RuleEngine) getUserID(c *fiber.Ctx) string {
	return c.Get("X-User-ID")
}

func (re *RuleEngine) getCountryFromIP(ip string) string {
	// Placeholder: implement IP to country lookup using a service like MaxMind
	return "US"
}

func (re *RuleEngine) checkGlobalDDOS(clientIP string) *Action {
	if !re.config.AnomalyDetectionRules.Global.DDOSDetection.Enabled {
		return nil
	}
	re.tracker.mu.Lock()
	defer re.tracker.mu.Unlock()
	now := time.Now()
	counter, exists := re.tracker.globalRequests[clientIP]
	if !exists || now.Sub(counter.LastReset) > time.Minute {
		re.tracker.globalRequests[clientIP] = &RequestCounter{
			Count:     1,
			LastReset: now,
		}
		return nil
	}
	counter.Count++
	threshold := re.config.AnomalyDetectionRules.Global.DDOSDetection.Threshold.RequestsPerMinute
	if counter.Count > threshold {
		for _, action := range re.config.AnomalyDetectionRules.Global.DDOSDetection.Actions {
			if re.isActionTriggered(nil, clientIP, "", action) {
				return &action
			}
		}
	}
	return nil
}

func (re *RuleEngine) checkMITM(c *fiber.Ctx) *Action {
	if !re.config.AnomalyDetectionRules.Global.MITMDetection.Enabled {
		return nil
	}
	scheme := c.Protocol()
	if xfProto := c.Get("X-Forwarded-Proto"); xfProto != "" {
		scheme = strings.ToLower(strings.TrimSpace(strings.Split(xfProto, ",")[0]))
	}
	if scheme != "https" {
		return nil
	}
	indicators := re.config.AnomalyDetectionRules.Global.MITMDetection.Indicators
	for _, indicator := range indicators {
		switch indicator {
		case "invalid_ssl_certificate":
			if re.hasInvalidSSLCert(c) {
				return &re.config.AnomalyDetectionRules.Global.MITMDetection.Actions[0]
			}
		case "abnormal_tls_handshake":
			if re.hasAbnormalTLSHandshake(c) {
				return &re.config.AnomalyDetectionRules.Global.MITMDetection.Actions[0]
			}
		case "suspicious_user_agent":
			if re.hasSuspiciousUserAgent(c) {
				return &re.config.AnomalyDetectionRules.Global.MITMDetection.Actions[0]
			}
		}
	}
	return nil
}

func (re *RuleEngine) hasInvalidSSLCert(c *fiber.Ctx) bool {
	// Placeholder for SSL cert validation logic, should be implemented as needed
	return false
}

func (re *RuleEngine) hasAbnormalTLSHandshake(c *fiber.Ctx) bool {
	// Placeholder for abnormal TLS handshake detection logic, should be implemented as needed
	return false
}

func (re *RuleEngine) hasSuspiciousUserAgent(c *fiber.Ctx) bool {
	userAgent := c.Get("User-Agent")
	patterns := re.config.AnomalyDetectionRules.Global.MITMDetection.SuspiciousUserAgents
	if len(patterns) == 0 {
		return false
	}
	ua := strings.ToLower(userAgent)
	for _, pattern := range patterns {
		if strings.Contains(ua, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

var ruleHandlers = map[string]func(re *RuleEngine, c *fiber.Ctx, params map[string]interface{}) bool{
	"businessHours": func(re *RuleEngine, c *fiber.Ctx, params map[string]interface{}) bool {
		endpoint := c.Path()
		if endpoint != "/api/login" {
			return false
		}
		now := time.Now()
		timezone, ok := params["timezone"].(string)
		if !ok {
			return false
		}
		loc, err := time.LoadLocation(timezone)
		if err != nil {
			return false
		}
		localNow := now.In(loc)
		startTimeStr, ok := params["startTime"].(string)
		if !ok {
			return false
		}
		endTimeStr, ok := params["endTime"].(string)
		if !ok {
			return false
		}
		start, _ := time.Parse("15:04", startTimeStr)
		end, _ := time.Parse("15:04", endTimeStr)
		startTime := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), start.Hour(), start.Minute(), 0, 0, loc)
		endTime := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), end.Hour(), end.Minute(), 0, 0, loc)
		return localNow.Before(startTime) || localNow.After(endTime)
	},
	"businessRegion": func(re *RuleEngine, c *fiber.Ctx, params map[string]interface{}) bool {
		endpoint := c.Path()
		if endpoint != "/api/login" {
			return false
		}
		clientIP := re.getClientIP(c)
		country := re.getCountryFromIP(clientIP)
		allowedCountries, ok := params["allowedCountries"].([]interface{})
		if !ok {
			return false
		}
		for _, a := range allowedCountries {
			if aStr, ok := a.(string); ok && aStr == country {
				return false
			}
		}
		return true
	},
	"protectedRoute": func(re *RuleEngine, c *fiber.Ctx, params map[string]interface{}) bool {
		endpoint := c.Path()
		protectedRoutes, ok := params["protectedRoutes"].([]interface{})
		if !ok {
			return false
		}
		protected := false
		for _, r := range protectedRoutes {
			if rStr, ok := r.(string); ok && strings.HasPrefix(endpoint, rStr) {
				protected = true
				break
			}
		}
		if !protected {
			return false
		}
		header, ok := params["loginCheckHeader"].(string)
		if !ok {
			header = "Authorization"
		}
		return c.Get(header) == ""
	},
	"sessionHijacking": func(re *RuleEngine, c *fiber.Ctx, params map[string]interface{}) bool {
		userID := re.getUserID(c)
		if userID == "" {
			return false
		}
		userAgent := c.Get("User-Agent")
		re.tracker.mu.Lock()
		defer re.tracker.mu.Unlock()
		sessions, exists := re.tracker.userSessions[userID]
		if !exists {
			sessions = []*SessionInfo{}
		}
		now := time.Now()
		sessionTimeoutStr, ok := params["sessionTimeout"].(string)
		if !ok {
			sessionTimeoutStr = "24h"
		}
		timeout, _ := time.ParseDuration(sessionTimeoutStr)
		// Clean old sessions
		validSessions := []*SessionInfo{}
		for _, s := range sessions {
			if now.Sub(s.Created) < timeout {
				validSessions = append(validSessions, s)
			}
		}
		// Check if this UserAgent exists
		found := false
		for _, s := range validSessions {
			if s.UA == userAgent {
				found = true
				break
			}
		}
		maxConcurrent, ok := params["maxConcurrentSessions"].(float64)
		if !ok {
			maxConcurrent = 3
		}
		if !found {
			if len(validSessions) >= int(maxConcurrent) {
				return true
			}
			validSessions = append(validSessions, &SessionInfo{
				UA:      userAgent,
				Created: now,
			})
		}
		re.tracker.userSessions[userID] = validSessions
		return false
	},
}

func (re *RuleEngine) checkRule(c *fiber.Ctx, rule Rule) *Action {
	if !rule.Enabled {
		return nil
	}
	handler, exists := ruleHandlers[rule.Type]
	if !exists {
		return nil
	}
	triggered := handler(re, c, rule.Params)
	if triggered && len(rule.Actions) > 0 {
		return &rule.Actions[0]
	}
	return nil
}

func (re *RuleEngine) checkEndpointRateLimit(c *fiber.Ctx, clientIP, endpoint string) *Action {
	rules, exists := re.config.AnomalyDetectionRules.APIEndpoints[endpoint]
	if !exists {
		return nil
	}
	re.tracker.mu.Lock()
	defer re.tracker.mu.Unlock()
	if re.tracker.endpointRequests[clientIP] == nil {
		re.tracker.endpointRequests[clientIP] = make(map[string]*RequestCounter)
	}
	now := time.Now()
	counter, exists := re.tracker.endpointRequests[clientIP][endpoint]
	if !exists || now.Sub(counter.LastReset) > time.Minute {
		re.tracker.endpointRequests[clientIP][endpoint] = &RequestCounter{
			Count:     1,
			LastReset: now,
			Burst:     1,
		}
		return nil
	}
	counter.Count++
	counter.Burst++
	if rules.RateLimit.Burst > 0 && counter.Burst > rules.RateLimit.Burst {
		for _, action := range rules.Actions {
			if action.Type == "jitter_warning" {
				if re.isActionTriggered(c, clientIP, endpoint, action) {
					return &action
				}
			}
		}
	}
	if now.Sub(counter.LastReset) > time.Minute {
		counter.Burst = 0
	}
	if counter.Count > rules.RateLimit.RequestsPerMinute {
		for _, action := range rules.Actions {
			if action.Type == "rate_limit" || action.Type == "jitter_warning" {
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

// isActionTriggered checks if an action's trigger is satisfied, fully config-driven.
func (re *RuleEngine) isActionTriggered(c *fiber.Ctx, clientIP, endpoint string, action Action) bool {
	if action.Trigger == nil {
		return true // No trigger, always triggered
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
	key := re.makeTriggerKey(scope, clientIP, endpoint, method, 0)
	if re.tracker.actionCounters[counterType] == nil {
		re.tracker.actionCounters[counterType] = make(map[string]*GenericCounter)
	}
	counter, exists := re.tracker.actionCounters[counterType][key]
	now := time.Now()
	if !exists || (window > 0 && now.Sub(counter.First) > window) {
		re.tracker.actionCounters[counterType][key] = &GenericCounter{
			Count: 1,
			First: now,
		}
		return false
	}
	counter.Count++
	if window == 0 {
		return counter.Count >= threshold
	} else if now.Sub(counter.First) <= window && counter.Count >= threshold {
		return true
	}
	return false
}

// evaluateTriggers increments and evaluates generic, config-driven triggers for this request.
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
		key := re.makeTriggerKey(scope, clientIP, endpoint, c.Method(), idx)
		if re.tracker.actionCounters[counterType] == nil {
			re.tracker.actionCounters[counterType] = make(map[string]*GenericCounter)
		}
		counter, exists := re.tracker.actionCounters[counterType][key]
		if !exists || (window > 0 && now.Sub(counter.First) > window) {
			re.tracker.actionCounters[counterType][key] = &GenericCounter{
				Count: 1,
				First: now,
			}
			continue
		}
		counter.Count++
		if window == 0 {
			if counter.Count >= threshold {
				return &action
			}
		} else if now.Sub(counter.First) <= window && counter.Count >= threshold {
			return &action
		}
	}
	return nil
}

// makeTriggerKey creates a stable key for grouping trigger counters.
func (re *RuleEngine) makeTriggerKey(scope, clientIP, endpoint, method string, actionIdx int) string {
	switch scope {
	case "client":
		return fmt.Sprintf("client|%s|action|%d", clientIP, actionIdx)
	case "client_endpoint_method":
		return fmt.Sprintf("client|%s|endpoint|%s|method|%s|action|%d", clientIP, endpoint, method, actionIdx)
	default: // "client_endpoint"
		return fmt.Sprintf("client|%s|endpoint|%s|action|%d", clientIP, endpoint, actionIdx)
	}
}

func (re *RuleEngine) applyAction(c *fiber.Ctx, action *Action, clientIP string) error {
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

func (re *RuleEngine) applyJitterWarning(c *fiber.Ctx, action *Action) error {
	if len(action.JitterRangeMs) == 2 {
		minVal := action.JitterRangeMs[0]
		maxVal := action.JitterRangeMs[1]
		jitter := time.Duration(rand.Intn(maxVal-minVal)+minVal) * time.Millisecond
		time.Sleep(jitter)
	}
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
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "rate_limit",
	})
}

func (re *RuleEngine) applyTemporaryBan(c *fiber.Ctx, action *Action, clientIP string) error {
	duration, err := time.ParseDuration(action.Duration)
	if err != nil {
		duration = 10 * time.Minute
	}
	re.tracker.mu.Lock()
	re.tracker.bannedClients[clientIP] = &BanInfo{
		Until:      time.Now().Add(duration),
		Permanent:  false,
		Reason:     action.Response.Message,
		StatusCode: action.Response.Status,
	}
	re.tracker.mu.Unlock()
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error":        action.Response.Message,
		"type":         "temporary_ban",
		"duration":     duration.String(),
		"banned_until": time.Now().Add(duration).Format(time.RFC3339),
	})
}

func (re *RuleEngine) applyPermanentBan(c *fiber.Ctx, action *Action, clientIP string) error {
	re.tracker.mu.Lock()
	re.tracker.bannedClients[clientIP] = &BanInfo{
		Until:      time.Time{},
		Permanent:  true,
		Reason:     action.Response.Message,
		StatusCode: action.Response.Status,
	}
	re.tracker.mu.Unlock()
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "permanent_ban",
	})
}

func (re *RuleEngine) isBanned(clientIP string) *BanInfo {
	re.tracker.mu.RLock()
	defer re.tracker.mu.RUnlock()
	banInfo, exists := re.tracker.bannedClients[clientIP]
	if !exists {
		return nil
	}
	if banInfo.Permanent {
		return banInfo
	}
	if time.Now().Before(banInfo.Until) {
		return banInfo
	}
	delete(re.tracker.bannedClients, clientIP)
	return nil
}

func (re *RuleEngine) AnomalyDetectionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientIP := re.getClientIP(c)
		endpoint := c.Path()
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
		if action := re.checkMITM(c); action != nil {
			return re.applyAction(c, action, clientIP)
		}
		if action := re.checkGlobalDDOS(clientIP); action != nil {
			return re.applyAction(c, action, clientIP)
		}
		for _, rule := range re.config.AnomalyDetectionRules.Global.Rules {
			if action := re.checkRule(c, rule); action != nil {
				return re.applyAction(c, action, clientIP)
			}
		}
		if action := re.checkEndpointRateLimit(c, clientIP, endpoint); action != nil {
			return re.applyAction(c, action, clientIP)
		}
		return c.Next()
	}
}

func (re *RuleEngine) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				re.cleanup()
			}
		}
	}()
}

func (re *RuleEngine) cleanup() {
	re.tracker.mu.Lock()
	defer re.tracker.mu.Unlock()
	now := time.Now()
	for ip, banInfo := range re.tracker.bannedClients {
		if !banInfo.Permanent && now.After(banInfo.Until) {
			delete(re.tracker.bannedClients, ip)
		}
	}
	for ip, counter := range re.tracker.globalRequests {
		if now.Sub(counter.LastReset) > 2*time.Minute {
			delete(re.tracker.globalRequests, ip)
		}
	}
	for ip, endpoints := range re.tracker.endpointRequests {
		for endpoint, counter := range endpoints {
			if now.Sub(counter.LastReset) > 2*time.Minute {
				delete(endpoints, endpoint)
			}
		}
		if len(endpoints) == 0 {
			delete(re.tracker.endpointRequests, ip)
		}
	}
	window := re.maxTriggerWindow()
	if window > 0 {
		for counterType, counters := range re.tracker.actionCounters {
			for key, counter := range counters {
				if now.Sub(counter.First) > window {
					delete(counters, key)
				}
			}
			if len(counters) == 0 {
				delete(re.tracker.actionCounters, counterType)
			}
		}
		// Clean user sessions
		for userID, sessions := range re.tracker.userSessions {
			validSessions := []*SessionInfo{}
			for _, s := range sessions {
				if now.Sub(s.Created) < 24*time.Hour { // Default cleanup, can be config
					validSessions = append(validSessions, s)
				}
			}
			if len(validSessions) == 0 {
				delete(re.tracker.userSessions, userID)
			} else {
				re.tracker.userSessions[userID] = validSessions
			}
		}
	}
}

// maxTriggerWindow scans all endpoint actions and returns the maximum Trigger.Within duration across all configured triggers.
// If no triggers are configured or none specify a window, returns 0.
func (re *RuleEngine) maxTriggerWindow() time.Duration {
	var maxWindow time.Duration
	for _, rules := range re.config.AnomalyDetectionRules.APIEndpoints {
		for _, action := range rules.Actions {
			if action.Trigger != nil {
				trigger := *action.Trigger
				if within, ok := trigger["within"].(string); ok && within != "" {
					if d, err := time.ParseDuration(within); err == nil {
						if d > maxWindow {
							maxWindow = d
						}
					}
				}
			}
		}
	}
	return maxWindow
}
