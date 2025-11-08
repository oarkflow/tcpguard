package tcpguard

import (
	"context"
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
	Type          string        `json:"type"`
	Priority      int           `json:"priority,omitempty"` // Higher values = higher priority
	Limit         string        `json:"limit,omitempty"`
	Duration      string        `json:"duration,omitempty"`
	JitterRangeMs []int         `json:"jitterRangeMs,omitempty"`
	Trigger       *Trigger      `json:"trigger,omitempty"`
	Response      Response      `json:"response"`
	Notify        *Notification `json:"notify,omitempty"`
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

type Notification struct {
	Channel string            `json:"channel"` // e.g., "slack", "webhook", "email", "log"
	Topic   string            `json:"topic"`   // e.g., webhook URL, Slack channel, email subject
	Message string            `json:"message"` // Message template with placeholders
	Details map[string]string `json:"details"` // Additional details with placeholders
}

type Credentials struct {
	Notifications map[string]map[string]interface{} `json:"notifications"`
}

type RuleEngine struct {
	config          *AnomalyConfig
	configDir       string
	Store           CounterStore
	rateLimiter     RateLimiter
	actionRegistry  *ActionHandlerRegistry
	pipelineReg     PipelineFunctionRegistry
	metrics         MetricsCollector
	validator       ConfigValidator
	notificationReg *NotificationRegistry
	sortedRules     []Rule // Cached sorted rules for performance
	rulesMutex      sync.RWMutex
	watcher         *fsnotify.Watcher
	watcherMutex    sync.Mutex
	// compiled access lists
	allowNets           []*net.IPNet
	denyNets            []*net.IPNet
	trustedProxyNets    []*net.IPNet
	trustProxy          bool
	banEscalationWindow time.Duration
	banEscalationThresh int
	// geolocation cache
	geoCache map[string]string
	geoMutex sync.RWMutex
}

func NewRuleEngine(configDir string, store CounterStore, rateLimiter RateLimiter, actionRegistry *ActionHandlerRegistry, pipelineReg PipelineFunctionRegistry, metrics MetricsCollector, validator ConfigValidator) (*RuleEngine, error) {
	config, err := loadConfig(configDir)
	if err != nil {
		return nil, err
	}

	credentials, err := loadCredentials(configDir)
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
		config:          config,
		configDir:       configDir,
		Store:           store,
		rateLimiter:     rateLimiter,
		actionRegistry:  actionRegistry,
		pipelineReg:     pipelineReg,
		metrics:         metrics,
		validator:       validator,
		notificationReg: NewNotificationRegistry(credentials),
		geoCache:        make(map[string]string),
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
	if ipAddr == "" {
		return defaultCountry
	}

	// Check cache first
	re.geoMutex.RLock()
	if country, exists := re.geoCache[ipAddr]; exists {
		re.geoMutex.RUnlock()
		return country
	}
	re.geoMutex.RUnlock()

	// Simple IP to country mapping for common cases
	switch {
	case strings.HasPrefix(ipAddr, "192.168."):
		country := "LOCAL"
		re.geoMutex.Lock()
		re.geoCache[ipAddr] = country
		re.geoMutex.Unlock()
		return country
	case strings.HasPrefix(ipAddr, "10."):
		country := "LOCAL"
		re.geoMutex.Lock()
		re.geoCache[ipAddr] = country
		re.geoMutex.Unlock()
		return country
	case strings.HasPrefix(ipAddr, "172."):
		country := "LOCAL"
		re.geoMutex.Lock()
		re.geoCache[ipAddr] = country
		re.geoMutex.Unlock()
		return country
	default:
		// Use external service with timeout and error handling
		country := re.callGeolocationAPI(ipAddr, defaultCountry)
		re.geoMutex.Lock()
		re.geoCache[ipAddr] = country
		re.geoMutex.Unlock()
		return country
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

func (re *RuleEngine) applyAction(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
	if re.actionRegistry != nil {
		if handler, exists := re.actionRegistry.Get(action.Type); exists {
			meta := ActionMeta{
				ClientIP: clientIP,
				Endpoint: c.Path(),
				UserID:   re.GetUserID(c),
			}
			return handler.Handle(context.Background(), c, *action, meta, re.Store, re.notificationReg, ruleName)
		}
	}
	// Fallback to built-in handlers
	switch action.Type {
	case "jitter_warning":
		return re.applyJitterWarning(c, action, clientIP, ruleName)
	case "rate_limit":
		return re.applyRateLimit(c, action, clientIP, ruleName)
	case "temporary_ban":
		return re.applyTemporaryBan(c, action, clientIP, ruleName)
	case "permanent_ban":
		return re.applyPermanentBan(c, action, clientIP, ruleName)
	}
	return nil
}

func (re *RuleEngine) applyActionSideEffects(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
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

		// Send notification if configured
		if action.Notify != nil && re.notificationReg != nil {
			meta := ActionMeta{
				ClientIP: clientIP,
				Endpoint: c.Path(),
				UserID:   re.GetUserID(c),
			}
			sendActionNotification(context.Background(), action.Notify, meta, action.Type, ruleName, re.notificationReg)
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
		// Send notification if configured
		if action.Notify != nil && re.notificationReg != nil {
			meta := ActionMeta{
				ClientIP: clientIP,
				Endpoint: c.Path(),
				UserID:   re.GetUserID(c),
			}
			sendActionNotification(context.Background(), action.Notify, meta, action.Type, ruleName, re.notificationReg)
		}

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
		return re.applyAction(c, action, clientIP, ruleName)
	}
}

func (re *RuleEngine) applyActionResponse(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
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
		return re.applyAction(c, action, clientIP, ruleName)
	}
}

func (re *RuleEngine) applyJitterWarning(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
	// Send notification if configured
	if action.Notify != nil && re.notificationReg != nil {
		meta := ActionMeta{
			ClientIP: clientIP,
			Endpoint: c.Path(),
			UserID:   re.GetUserID(c),
		}
		sendActionNotification(context.Background(), action.Notify, meta, action.Type, ruleName, re.notificationReg)
	}

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

func (re *RuleEngine) applyRateLimit(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
	// Send notification if configured
	if action.Notify != nil && re.notificationReg != nil {
		meta := ActionMeta{
			ClientIP: clientIP,
			Endpoint: c.Path(),
			UserID:   re.GetUserID(c),
		}
		sendActionNotification(context.Background(), action.Notify, meta, action.Type, ruleName, re.notificationReg)
	}

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

func (re *RuleEngine) applyTemporaryBan(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
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

	// Send notification if configured
	if action.Notify != nil && re.notificationReg != nil {
		meta := ActionMeta{
			ClientIP: clientIP,
			Endpoint: c.Path(),
			UserID:   re.GetUserID(c),
		}
		sendActionNotification(context.Background(), action.Notify, meta, action.Type, ruleName, re.notificationReg)
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

func (re *RuleEngine) applyPermanentBan(c *fiber.Ctx, action *Action, clientIP, ruleName string) error {
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

	// Send notification if configured
	if action.Notify != nil && re.notificationReg != nil {
		meta := ActionMeta{
			ClientIP: clientIP,
			Endpoint: c.Path(),
			UserID:   re.GetUserID(c),
		}
		sendActionNotification(context.Background(), action.Notify, meta, action.Type, ruleName, re.notificationReg)
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
						if err := re.applyActionSideEffects(c, &a, clientIP, rule.Name); err != nil {
							return err
						}
					}
				}

				// Apply the response from the most severe action
				if mostSevereAction != nil {
					return re.applyActionResponse(c, mostSevereAction, clientIP, rule.Name)
				}

				// Return early after applying actions for triggered global rule
				return nil
			}
		}
		if action := re.checkEndpointRateLimit(c, clientIP, endpoint); action != nil {
			return re.applyAction(c, action, clientIP, endpoint)
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
func (re *RuleEngine) GetRules() map[string]interface{} {
	re.rulesMutex.RLock()
	defer re.rulesMutex.RUnlock()

	return map[string]interface{}{
		"global":    re.config.AnomalyDetectionRules.Global.Rules,
		"endpoints": re.config.AnomalyDetectionRules.APIEndpoints,
	}
}

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

	// Check if metrics is accessible
	if re.metrics == nil {
		return fmt.Errorf("rule engine metrics is not initialized")
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

	newCredentials, err := loadCredentials(re.configDir)
	if err != nil {
		return fmt.Errorf("failed to load credentials: %v", err)
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

	// Update notification registry with new credentials
	re.notificationReg = NewNotificationRegistry(newCredentials)

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
