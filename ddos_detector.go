package tcpguard

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// AttackFinding represents a concrete detection produced by the advanced DDoS engine.
type AttackFinding struct {
	Name     string             `json:"name"`
	Layer    string             `json:"layer"`
	Severity string             `json:"severity"`
	Reason   string             `json:"reason"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
}

// DDoSDetectionVerdict contains all detections for a single request evaluation.
type DDoSDetectionVerdict struct {
	Triggered bool            `json:"triggered"`
	Findings  []AttackFinding `json:"findings"`
}

type ddosRuleParams struct {
	Window            string                          `json:"window"`
	Telemetry         map[string]string               `json:"telemetry"`
	Attacks           map[string]AttackConfigOverride `json:"attacks"`
	RequestsPerMinute int                             `json:"requestsPerMinute"`
	Threshold         struct {
		RequestsPerMinute int `json:"requestsPerMinute"`
	} `json:"threshold"`
}

type AttackConfigOverride struct {
	Enabled    *bool              `json:"enabled,omitempty"`
	Severity   string             `json:"severity,omitempty"`
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
}

// TelemetrySnapshot aggregates the contextual signals used by the detectors.
type TelemetrySnapshot struct {
	Timestamp           time.Time
	ClientIP            string
	Endpoint            string
	Method              string
	Path                string
	UserAgent           string
	HeaderSize          int
	HeaderCount         int
	BodySize            int
	QueryParameterCount int
	QueryRandomness     float64
	CacheControl        string
	RangeHeader         string
	HasCookie           bool
	HasReferer          bool
	RequestPerMinute    float64
	RequestPerSecond    float64
	PathDiversity       float64
	UserAgentDiversity  int
	Additional          map[string]float64
}

type detectionContext struct {
	ctx      *Context
	snapshot *TelemetrySnapshot
}

type attackConfig struct {
	enabled    bool
	severity   string
	thresholds map[string]float64
}

type detectionOutcome struct {
	triggered bool
	reason    string
	metrics   map[string]float64
}

// AdvancedDDoSCondition evaluates all registered attack detectors in a single pass.
func AdvancedDDoSCondition(ctx *Context) any {
	if ctx == nil || ctx.RuleEngine == nil || ctx.FiberCtx == nil {
		return false
	}

	params, err := parseDDoSRuleParams(ctx.Results)
	if err != nil {
		fmt.Printf("ddos: failed to parse params: %v\n", err)
		return false
	}

	if params == nil {
		return false
	}

	if params.useLegacyThreshold() {
		rpm := params.legacyRequestsPerMinute()
		triggered := evaluateLegacyDDoS(ctx, rpm)
		ctx.Results["ddosVerdict"] = DDoSDetectionVerdict{Triggered: triggered}
		return triggered
	}

	snapshot := buildTelemetrySnapshot(ctx, params)
	verdict := evaluateAdvancedDetectors(ctx, snapshot, params)
	ctx.Results["ddosVerdict"] = verdict
	return verdict.Triggered
}

func parseDDoSRuleParams(results map[string]any) (*ddosRuleParams, error) {
	if results == nil {
		return &ddosRuleParams{}, nil
	}
	raw, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	var params ddosRuleParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return &params, nil
}

func (p *ddosRuleParams) useLegacyThreshold() bool {
	if p == nil {
		return false
	}
	if len(p.Attacks) > 0 {
		return false
	}
	return p.legacyRequestsPerMinute() > 0
}

func (p *ddosRuleParams) legacyRequestsPerMinute() int {
	if p == nil {
		return 0
	}
	if p.RequestsPerMinute > 0 {
		return p.RequestsPerMinute
	}
	if p.Threshold.RequestsPerMinute > 0 {
		return p.Threshold.RequestsPerMinute
	}
	return 0
}

func evaluateLegacyDDoS(ctx *Context, rpm int) bool {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}
	if rpm <= 0 {
		rpm = 100
	}
	count, _ := getGlobalRequestStats(ctx.FiberCtx)
	return float64(count) > float64(rpm)
}

func evaluateAdvancedDetectors(ctx *Context, snapshot *TelemetrySnapshot, params *ddosRuleParams) DDoSDetectionVerdict {
	verdict := DDoSDetectionVerdict{}
	if snapshot == nil {
		return verdict
	}

	for name, def := range attackDefinitions {
		cfg := def.buildConfig(name, params)
		if !cfg.enabled {
			continue
		}
		outcome := def.Detector(detectionContext{ctx: ctx, snapshot: snapshot}, cfg)
		if outcome.triggered {
			finding := AttackFinding{
				Name:     name,
				Layer:    def.Layer,
				Severity: cfg.severity,
				Reason:   outcome.reason,
				Metrics:  outcome.metrics,
			}
			verdict.Findings = append(verdict.Findings, finding)
		}
	}

	verdict.Triggered = len(verdict.Findings) > 0
	if verdict.Triggered && ctx != nil && ctx.RuleEngine != nil {
		if ctx.RuleEngine.metrics != nil {
			for _, finding := range verdict.Findings {
				ctx.RuleEngine.metrics.IncrementCounter("ddos_detection_total", map[string]string{
					"attack":   finding.Name,
					"layer":    finding.Layer,
					"severity": finding.Severity,
				})
			}
		}
		if ctx.RuleEngine.detectionLedger != nil {
			ctx.RuleEngine.detectionLedger.Record(DetectionEvent{
				ClientIP: snapshot.ClientIP,
				Endpoint: snapshot.Endpoint,
				Findings: verdict.Findings,
			})
		}
	}
	return verdict
}

func buildTelemetrySnapshot(ctx *Context, params *ddosRuleParams) *TelemetrySnapshot {
	c := ctx.FiberCtx
	snapshot := &TelemetrySnapshot{
		Timestamp:    time.Now(),
		ClientIP:     ctx.RuleEngine.GetClientIP(c),
		Endpoint:     c.Path(),
		Method:       c.Method(),
		Path:         c.Path(),
		UserAgent:    c.Get("User-Agent"),
		CacheControl: c.Get("Cache-Control"),
		RangeHeader:  c.Get("Range"),
		HasCookie:    c.Get("Cookie") != "",
		HasReferer:   c.Get("Referer") != "",
		Additional:   make(map[string]float64),
	}

	headerSize, headerCount := computeHeaderStats(c)
	snapshot.HeaderSize = headerSize
	snapshot.HeaderCount = headerCount
	snapshot.BodySize = len(c.Body())
	snapshot.QueryParameterCount = len(c.Queries())
	snapshot.QueryRandomness = estimateQueryRandomness(c)

	if ctx.RuleEngine != nil && ctx.RuleEngine.requestProfiler != nil {
		profile := ctx.RuleEngine.requestProfiler.Snapshot(snapshot.ClientIP, snapshot.Timestamp)
		snapshot.PathDiversity = profile.PathDiversityScore
		snapshot.UserAgentDiversity = profile.UniqueUserAgents
	}

	count, reset := getGlobalRequestStats(c)
	if count == 0 && ctx.RuleEngine != nil && ctx.RuleEngine.Store != nil && snapshot.ClientIP != "" {
		if counter, err := ctx.RuleEngine.Store.GetGlobal(snapshot.ClientIP); err == nil && counter != nil {
			count = counter.Count
			reset = counter.LastReset
		}
	}
	if count > 0 {
		snapshot.RequestPerMinute = float64(count)
		elapsed := time.Since(reset).Seconds()
		if elapsed <= 0 {
			elapsed = 60
		}
		snapshot.RequestPerSecond = float64(count) / math.Max(elapsed, 1)
	}

	collectTelemetryOverrides(c, params, snapshot)
	if ctx.RuleEngine != nil && ctx.RuleEngine.telemetryStore != nil {
		if extra := ctx.RuleEngine.telemetryStore.Snapshot(snapshot.ClientIP); len(extra) > 0 {
			for metric, value := range extra {
				if _, exists := snapshot.Additional[metric]; !exists {
					snapshot.Additional[metric] = value
				}
			}
		}
	}
	trackRangeMetrics(ctx, snapshot)
	return snapshot
}

func collectTelemetryOverrides(c *fiber.Ctx, params *ddosRuleParams, snapshot *TelemetrySnapshot) {
	if snapshot.Additional == nil {
		snapshot.Additional = make(map[string]float64)
	}

	if params != nil && params.Telemetry != nil {
		for metric, key := range params.Telemetry {
			if key == "" {
				continue
			}
			if val, ok := getFloatFromLocals(c, key); ok {
				snapshot.Additional[metric] = val
			}
		}
	}

	if payload, ok := c.Locals("tcpguard.telemetry").(map[string]any); ok {
		for metric, raw := range payload {
			if _, exists := snapshot.Additional[metric]; exists {
				continue
			}
			if val, ok := toFloat(raw); ok {
				snapshot.Additional[metric] = val
			}
		}
	}
}

func trackRangeMetrics(ctx *Context, snapshot *TelemetrySnapshot) {
	if snapshot.RangeHeader == "" || ctx == nil || ctx.RuleEngine == nil || ctx.RuleEngine.Store == nil {
		return
	}
	key := fmt.Sprintf("range_requests|%s", snapshot.ClientIP)
	count, _, _ := ctx.RuleEngine.Store.IncrementActionCounter(key, time.Minute)
	snapshot.Additional["range_request_count"] = float64(count)

	if size := parseRangeHeaderSize(snapshot.RangeHeader); size > 0 && size < 1024 {
		microKey := fmt.Sprintf("micro_range|%s", snapshot.ClientIP)
		microCount, _, _ := ctx.RuleEngine.Store.IncrementActionCounter(microKey, time.Minute)
		snapshot.Additional["micro_range_count"] = float64(microCount)
	}
}

func parseRangeHeaderSize(value string) int {
	if value == "" {
		return 0
	}
	parts := strings.Split(strings.TrimSpace(value), "=")
	if len(parts) != 2 {
		return 0
	}
	ranges := strings.Split(parts[1], ",")
	if len(ranges) == 0 {
		return 0
	}
	section := strings.TrimSpace(ranges[0])
	bounds := strings.Split(section, "-")
	if len(bounds) != 2 {
		return 0
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
	if err1 != nil || err2 != nil || end < start {
		return 0
	}
	return end - start + 1
}

func computeHeaderStats(c *fiber.Ctx) (size int, count int) {
	headers := c.GetReqHeaders()
	for key, value := range headers {
		count++
		size += len(key) + len(value)
	}
	return
}

func estimateQueryRandomness(c *fiber.Ctx) float64 {
	queries := c.Queries()
	if len(queries) == 0 {
		return 0
	}
	suspicious := 0
	for key, value := range queries {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "ts") || strings.Contains(lower, "nonce") || strings.Contains(lower, "rand") {
			suspicious++
			continue
		}
		if len(value) > 16 && isMostlyNumeric(value) {
			suspicious++
		}
	}
	return float64(suspicious) / float64(len(queries))
}

func isMostlyNumeric(value string) bool {
	digits := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if len(value) == 0 {
		return false
	}
	return float64(digits)/float64(len(value)) > 0.6
}

func (ts *TelemetrySnapshot) Metric(name string, fallback float64) float64 {
	if ts == nil {
		return fallback
	}
	if ts.Additional != nil {
		if val, ok := ts.Additional[name]; ok {
			return val
		}
	}
	switch name {
	case "request_rate":
		if ts.RequestPerSecond > 0 {
			return ts.RequestPerSecond
		}
		return ts.RequestPerMinute / 60
	case "path_diversity":
		if ts.PathDiversity > 0 {
			return ts.PathDiversity
		}
	}
	return fallback
}

func getGlobalRequestStats(c *fiber.Ctx) (int, time.Time) {
	if c == nil {
		return 0, time.Now()
	}
	countAny := c.Locals(localGlobalCountKey)
	resetAny := c.Locals(localGlobalResetKey)
	count, _ := countAny.(int)
	var reset time.Time
	if resetVal, ok := resetAny.(time.Time); ok {
		reset = resetVal
	}
	return count, reset
}

func getFloatFromLocals(c *fiber.Ctx, key string) (float64, bool) {
	if c == nil {
		return 0, false
	}
	value := c.Locals(key)
	return toFloat(value)
}

func toFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}
