package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
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
	Rules map[string]Rule `json:"rules"`
}

type DDOSDetection struct {
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Threshold Threshold `json:"threshold"`
	Actions   []Action  `json:"actions"`
}

type MITMDetection struct {
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	Indicators           []string `json:"indicators"`
	Actions              []Action `json:"actions"`
	SuspiciousUserAgents []string `json:"suspiciousUserAgents,omitempty"`
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
	Nodes []PipelineNode `json:"nodes"`
	Edges []PipelineEdge `json:"edges"`
}

type Rule struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Enabled  bool           `json:"enabled"`
	Params   map[string]any `json:"params"`
	Pipeline *Pipeline      `json:"pipeline,omitempty"`
	Actions  []Action       `json:"actions"`
}

type PipelineContext struct {
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
	Store          CounterStore
	rateLimiter    RateLimiter
	actionRegistry *ActionHandlerRegistry
	pipelineReg    PipelineFunctionRegistry
	metrics        MetricsCollector
}

// Data structures used by the CounterStore interface
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

func NewRuleEngine(configDir string, store CounterStore, rateLimiter RateLimiter, actionRegistry *ActionHandlerRegistry, pipelineReg PipelineFunctionRegistry, metrics MetricsCollector) (*RuleEngine, error) {
	config, err := loadConfig(configDir)
	if err != nil {
		return nil, err
	}
	ruleEngine := &RuleEngine{
		config:         config,
		Store:          store,
		rateLimiter:    rateLimiter,
		actionRegistry: actionRegistry,
		pipelineReg:    pipelineReg,
		metrics:        metrics,
	}
	ruleEngine.startCleanupRoutine()
	return ruleEngine, nil
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

		filePath := globalDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read global rule file %s: %v", file.Name(), err)
		}

		var rule Rule
		if err := json.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("failed to parse global rule file %s: %v", file.Name(), err)
		}

		config.AnomalyDetectionRules.Global.Rules[rule.Name] = rule
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
	if ip := c.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := c.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return c.IP()
}

func (re *RuleEngine) GetUserID(c *fiber.Ctx) string {
	return c.Get("X-User-ID")
}

func (re *RuleEngine) GetCountryFromIP(ip string, defaultCountry string) string {
	return "US"
}

func (re *RuleEngine) checkRule(c *fiber.Ctx, rule Rule) *Action {
	if !rule.Enabled {
		return nil
	}

	if rule.Pipeline != nil {
		triggered := re.executePipeline(c, rule.Pipeline, rule.Params)
		if triggered {
			clientIP := re.GetClientIP(c)
			if a := re.evaluateTriggers(c, clientIP, "", rule.Actions); a != nil {
				return a
			}
			if len(rule.Actions) > 0 {
				return &rule.Actions[0]
			}
		}
		return nil
	}
	handler, exists := re.pipelineReg.Get(rule.Type)
	if !exists {
		return nil
	}
	ctx := &PipelineContext{
		RuleEngine: re,
		FiberCtx:   c,
		Results:    make(map[string]any),
		Triggered:  false,
	}
	for k, v := range rule.Params {
		ctx.Results[k] = v
	}
	result := handler(ctx)
	if triggered, ok := result.(bool); ok && triggered {
		clientIP := re.GetClientIP(c)
		if a := re.evaluateTriggers(c, clientIP, "", rule.Actions); a != nil {
			return a
		}
		if len(rule.Actions) > 0 {
			return &rule.Actions[0]
		}
	}
	return nil
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
		return re.Store.SetBan(clientIP, ban)
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
	return nil
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

		// Check all global rules
		for _, rule := range re.config.AnomalyDetectionRules.Global.Rules {
			if !rule.Enabled {
				continue
			}
			triggered := false
			if rule.Pipeline != nil {
				triggered = re.executePipeline(c, rule.Pipeline, rule.Params)
			} else {
				handler, exists := re.pipelineReg.Get(rule.Type)
				if exists {
					ctx := &PipelineContext{
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

				// First pass: identify the most severe action
				for _, a := range rule.Actions {
					if re.isActionTriggered(c, clientIP, "", a) {
						if a.Type == "temporary_ban" || a.Type == "permanent_ban" {
							mostSevereAction = &a
							break // Ban actions take highest priority
						} else if a.Type == "rate_limit" && mostSevereAction == nil {
							mostSevereAction = &a
						}
					}
				}

				// Second pass: apply all actions for side effects only
				for _, a := range rule.Actions {
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
	ctx := &PipelineContext{
		RuleEngine: re,
		FiberCtx:   c,
		Results:    make(map[string]any),
		Triggered:  false,
	}
	for k, v := range ruleParams {
		ctx.Results[k] = v
	}
	adjList := make(map[string][]string)
	inDegree := make(map[string]int)
	nodeMap := make(map[string]PipelineNode)
	for _, node := range pipeline.Nodes {
		nodeMap[node.ID] = node
		inDegree[node.ID] = 0
	}
	for _, edge := range pipeline.Edges {
		adjList[edge.From] = append(adjList[edge.From], edge.To)
		inDegree[edge.To]++
	}
	var queue []string
	for nodeID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, nodeID)
		}
	}
	executed := make(map[string]bool)
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
					if triggered, ok := result.(bool); ok && triggered {
						ctx.Triggered = true
					}
				}
			}
		}
		executed[currentID] = true
		for _, neighbor := range adjList[currentID] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}
	return ctx.Triggered
}
