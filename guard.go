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
	DDOSDetection DDOSDetection `json:"ddosDetection"`
	MITMDetection MITMDetection `json:"mitmDetection"`
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

type Trigger struct {
	FailedLogins int    `json:"failedLogins"`
	Within       string `json:"within"`
}

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type ClientTracker struct {
	mu               sync.RWMutex
	globalRequests   map[string]*RequestCounter
	endpointRequests map[string]map[string]*RequestCounter
	bannedClients    map[string]*BanInfo
	failedLogins     map[string]*FailedLoginTracker
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

type FailedLoginTracker struct {
	Count     int
	FirstFail time.Time
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
		failedLogins:     make(map[string]*FailedLoginTracker),
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
			return &action
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
	if c.Protocol() == "https" {
		return false
	}
	return false
}

func (re *RuleEngine) hasAbnormalTLSHandshake(c *fiber.Ctx) bool {
	if c.Protocol() == "https" {
		return false
	}
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
				return &action
			}
		}
	}
	// Align burst reset window with the per-minute rate limit window
	if now.Sub(counter.LastReset) > time.Minute {
		counter.Burst = 0
	}
	if counter.Count > rules.RateLimit.RequestsPerMinute {
		// If this endpoint defines a trigger, evaluate it without hardcoding endpoint paths
		for _, action := range rules.Actions {
			if action.Trigger != nil {
				if a := re.checkFailedLoginTrigger(clientIP, rules.Actions); a != nil {
					return a
				}
				break
			}
		}
		for _, action := range rules.Actions {
			if action.Type == "rate_limit" || action.Type == "jitter_warning" {
				return &action
			}
		}
	}
	return nil
}

func (re *RuleEngine) checkFailedLoginTrigger(clientIP string, actions []Action) *Action {
	tracker, exists := re.tracker.failedLogins[clientIP]
	if !exists {
		re.tracker.failedLogins[clientIP] = &FailedLoginTracker{
			Count:     1,
			FirstFail: time.Now(),
		}
		return nil
	}
	tracker.Count++
	for _, action := range actions {
		if action.Type == "temporary_ban" && action.Trigger != nil {
			duration, _ := time.ParseDuration(action.Trigger.Within)
			if tracker.Count >= action.Trigger.FailedLogins &&
				time.Since(tracker.FirstFail) <= duration {
				return &action
			}
		}
	}
	return nil
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
	// If the action specifies a duration, use it to inform clients when to retry
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
	// Use maximum trigger window from config to decide when to clean failed login trackers
	window := re.maxFailedLoginWindow()
	if window > 0 {
		for ip, tracker := range re.tracker.failedLogins {
			if now.Sub(tracker.FirstFail) > window {
				delete(re.tracker.failedLogins, ip)
			}
		}
	}
}

// maxFailedLoginWindow scans all endpoint actions and returns the maximum Trigger.Within duration.
// If no triggers are configured, returns 0.
func (re *RuleEngine) maxFailedLoginWindow() time.Duration {
	var maxWindow time.Duration
	for _, rules := range re.config.AnomalyDetectionRules.APIEndpoints {
		for _, action := range rules.Actions {
			if action.Trigger != nil && action.Trigger.Within != "" {
				if d, err := time.ParseDuration(action.Trigger.Within); err == nil {
					if d > maxWindow {
						maxWindow = d
					}
				}
			}
		}
	}
	return maxWindow
}
