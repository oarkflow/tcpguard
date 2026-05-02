package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// AnomalyFinding represents a single anomaly detection result.
type AnomalyFinding struct {
	Type     string             `json:"type"` // rate_anomaly, payload_entropy, geo_anomaly, temporal_anomaly, behavioral_drift, error_rate_anomaly, response_anomaly
	Severity string             `json:"severity"`
	Reason   string             `json:"reason"`
	Score    float64            `json:"score"` // 0.0 - 1.0
	Baseline map[string]float64 `json:"baseline,omitempty"`
	Current  map[string]float64 `json:"current,omitempty"`
}

// AnomalyDetectionVerdict contains all anomaly detections for a request evaluation.
type AnomalyDetectionVerdict struct {
	Triggered    bool             `json:"triggered"`
	Findings     []AnomalyFinding `json:"findings"`
	AnomalyScore float64          `json:"anomaly_score"` // aggregate (max of individual)
}

// anomalyRuleParams holds JSON-configurable parameters for anomaly detection.
type anomalyRuleParams struct {
	Detectors        map[string]AnomalyDetectorConfig `json:"detectors"`
	BaselineWindow   string                           `json:"baselineWindow"`   // e.g., "1h"
	BaselineScope    string                           `json:"baselineScope"`    // "client_endpoint" (default) or "client"
	SensitivityLevel string                           `json:"sensitivityLevel"` // "low", "medium", "high"
	MinSamples       int                              `json:"minSamples"`
}

// AnomalyDetectorConfig allows per-detector enable/disable/severity/thresholds.
type AnomalyDetectorConfig struct {
	Enabled    *bool              `json:"enabled,omitempty"`
	Severity   string             `json:"severity,omitempty"`
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
}

func (p *anomalyRuleParams) isDetectorEnabled(name string) bool {
	if p == nil || p.Detectors == nil {
		return true
	}
	cfg, ok := p.Detectors[name]
	if !ok {
		return true
	}
	if cfg.Enabled == nil {
		return true
	}
	return *cfg.Enabled
}

func (p *anomalyRuleParams) detectorSeverity(name, fallback string) string {
	if p == nil || p.Detectors == nil {
		return fallback
	}
	cfg, ok := p.Detectors[name]
	if !ok || cfg.Severity == "" {
		return fallback
	}
	return cfg.Severity
}

func (p *anomalyRuleParams) threshold(detector, key string, fallback float64) float64 {
	if p == nil || p.Detectors == nil {
		return fallback
	}
	cfg, ok := p.Detectors[detector]
	if !ok || cfg.Thresholds == nil {
		return fallback
	}
	if v, ok := cfg.Thresholds[key]; ok {
		return v
	}
	for _, alias := range thresholdAliases(detector, key) {
		if v, ok := cfg.Thresholds[alias]; ok {
			return v
		}
	}
	return fallback
}

func thresholdAliases(detector, key string) []string {
	switch detector + "." + key {
	case "rate_anomaly.sigmas", "response_anomaly.deviationSigmas":
		return []string{"zScoreThreshold"}
	case "payload_entropy.high":
		return []string{"maxEntropy"}
	case "payload_entropy.low":
		return []string{"minEntropy"}
	case "behavioral_drift.driftThreshold":
		return []string{"minSimilarity"}
	default:
		return nil
	}
}

func (p *anomalyRuleParams) sensitivityMultiplier() float64 {
	if p == nil {
		return 1.0
	}
	switch strings.ToLower(p.SensitivityLevel) {
	case "low":
		return 1.5
	case "high":
		return 0.6
	default:
		return 1.0
	}
}

func (p *anomalyRuleParams) minSamplesOrDefault() int {
	if p == nil || p.MinSamples <= 0 {
		return 10
	}
	return p.MinSamples
}

func (p *anomalyRuleParams) baselineKey(clientIP string, c fiber.Ctx) string {
	if p != nil && strings.EqualFold(p.BaselineScope, "client") {
		return clientIP
	}
	if c == nil {
		return clientIP
	}
	return clientIP + "|" + c.Method() + "|" + c.Path()
}

// ---------------------------------------------------------------------------
// RollingStats — online mean/variance computation
// ---------------------------------------------------------------------------

// RollingStats tracks streaming statistics for anomaly baseline detection.
type RollingStats struct {
	Count int
	Sum   float64
	SumSq float64
	Min   float64
	Max   float64
}

// Add records a new sample.
func (s *RollingStats) Add(value float64) {
	s.Count++
	s.Sum += value
	s.SumSq += value * value
	if s.Count == 1 {
		s.Min = value
		s.Max = value
	} else {
		if value < s.Min {
			s.Min = value
		}
		if value > s.Max {
			s.Max = value
		}
	}
}

// Mean returns the arithmetic mean.
func (s *RollingStats) Mean() float64 {
	if s.Count == 0 {
		return 0
	}
	return s.Sum / float64(s.Count)
}

// StdDev returns the population standard deviation.
func (s *RollingStats) StdDev() float64 {
	if s.Count < 2 {
		return 0
	}
	mean := s.Mean()
	variance := s.SumSq/float64(s.Count) - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

// IsAnomaly returns true if value exceeds mean + sigmas*stddev.
func (s *RollingStats) IsAnomaly(value float64, sigmas float64) bool {
	if s.Count < 2 {
		return false
	}
	threshold := s.Mean() + sigmas*s.StdDev()
	return value > threshold
}

// DeviationScore returns a normalized 0.0-1.0 deviation score.
func (s *RollingStats) DeviationScore(value float64) float64 {
	if s.Count < 2 {
		return 0
	}
	stddev := s.StdDev()
	if stddev == 0 {
		if value != s.Mean() {
			return 1.0
		}
		return 0
	}
	deviations := math.Abs(value-s.Mean()) / stddev
	// Normalize: 3 sigma = 1.0
	score := deviations / 3.0
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// ---------------------------------------------------------------------------
// IPBaseline — per-IP statistical baselines
// ---------------------------------------------------------------------------

// IPBaseline tracks rolling statistics per IP address.
type IPBaseline struct {
	RequestRate  RollingStats
	ResponseSize RollingStats
	ErrorRate    RollingStats
	PayloadSize  RollingStats
	PathEntropy  RollingStats
	LastUpdate   time.Time
	SampleCount  int

	// Behavioral fingerprint tracking.
	PathHistory   map[string]int // path -> access count
	MethodHistory map[string]int
	UAHistory     map[string]int
	HourHistogram [24]int

	// Geographic tracking.
	LastCountry string
	LastGeoTime time.Time
}

// BaselineTracker manages per-IP baselines.
type BaselineTracker struct {
	mu         sync.RWMutex
	baselines  map[string]*IPBaseline
	maxEntries int
	maxAge     time.Duration
	stopCh     chan struct{}
	stopped    sync.Once
}

// NewBaselineTracker creates a new baseline tracker with cleanup goroutine.
func NewBaselineTracker(maxEntries int, maxAge time.Duration) *BaselineTracker {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if maxAge <= 0 {
		maxAge = 1 * time.Hour
	}
	bt := &BaselineTracker{
		baselines:  make(map[string]*IPBaseline),
		maxEntries: maxEntries,
		maxAge:     maxAge,
		stopCh:     make(chan struct{}),
	}
	go bt.startCleanup()
	return bt
}

func (bt *BaselineTracker) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			bt.cleanup()
		case <-bt.stopCh:
			return
		}
	}
}

func (bt *BaselineTracker) cleanup() {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	cutoff := time.Now().Add(-bt.maxAge)
	for ip, baseline := range bt.baselines {
		if baseline.LastUpdate.Before(cutoff) {
			delete(bt.baselines, ip)
		}
	}
	// Cap entries if still over limit.
	if len(bt.baselines) > bt.maxEntries {
		// Remove oldest entries.
		toRemove := len(bt.baselines) - bt.maxEntries
		for ip, baseline := range bt.baselines {
			if toRemove <= 0 {
				break
			}
			if baseline.LastUpdate.Before(time.Now().Add(-bt.maxAge / 2)) {
				delete(bt.baselines, ip)
				toRemove--
			}
		}
	}
}

// Stop stops the cleanup goroutine.
func (bt *BaselineTracker) Stop() {
	bt.stopped.Do(func() {
		close(bt.stopCh)
	})
}

// GetOrCreate returns or creates a baseline for an IP.
func (bt *BaselineTracker) GetOrCreate(ip string) *IPBaseline {
	bt.mu.RLock()
	baseline := bt.baselines[ip]
	bt.mu.RUnlock()
	if baseline != nil {
		return baseline
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()
	if baseline = bt.baselines[ip]; baseline != nil {
		return baseline
	}
	baseline = &IPBaseline{
		PathHistory:   make(map[string]int),
		MethodHistory: make(map[string]int),
		UAHistory:     make(map[string]int),
		LastUpdate:    time.Now(),
	}
	bt.baselines[ip] = baseline
	return baseline
}

// Get returns a baseline for an IP (nil if not found).
func (bt *BaselineTracker) Get(ip string) *IPBaseline {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.baselines[ip]
}

// ---------------------------------------------------------------------------
// Package-level baseline tracker
// ---------------------------------------------------------------------------

var (
	anomalyTrackerMu    sync.RWMutex
	anomalyTrackerStore = make(map[*RuleEngine]*BaselineTracker)
)

func getAnomalyTracker(re *RuleEngine) *BaselineTracker {
	if re == nil {
		return nil
	}
	anomalyTrackerMu.RLock()
	tracker := anomalyTrackerStore[re]
	anomalyTrackerMu.RUnlock()
	if tracker != nil {
		return tracker
	}

	anomalyTrackerMu.Lock()
	defer anomalyTrackerMu.Unlock()
	if tracker = anomalyTrackerStore[re]; tracker != nil {
		return tracker
	}
	tracker = NewBaselineTracker(10000, time.Hour)
	anomalyTrackerStore[re] = tracker
	return tracker
}

// RemoveAnomalyTracker cleans up the baseline tracker for a RuleEngine.
func RemoveAnomalyTracker(re *RuleEngine) {
	if re == nil {
		return
	}
	anomalyTrackerMu.Lock()
	defer anomalyTrackerMu.Unlock()
	if tracker, exists := anomalyTrackerStore[re]; exists {
		tracker.Stop()
		delete(anomalyTrackerStore, re)
	}
}

// ---------------------------------------------------------------------------
// Anomaly detectors
// ---------------------------------------------------------------------------

// detectRateAnomaly compares current request rate against IP's historical baseline.
func detectRateAnomaly(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || ctx.FiberCtx == nil || baseline == nil {
		return nil
	}

	minSamples := params.minSamplesOrDefault()
	if baseline.RequestRate.Count < minSamples {
		return nil
	}

	sigmas := params.threshold("rate_anomaly", "sigmas", 3.0) * params.sensitivityMultiplier()

	// Get current request rate from context.
	var currentRate float64
	count, reset := getGlobalRequestStats(ctx.FiberCtx)
	if count > 0 {
		elapsed := time.Since(reset).Seconds()
		if elapsed <= 0 {
			elapsed = 60
		}
		currentRate = float64(count) / math.Max(elapsed, 1) * 60 // requests per minute
	}

	if currentRate <= 0 {
		return nil
	}

	if !baseline.RequestRate.IsAnomaly(currentRate, sigmas) {
		return nil
	}

	score := baseline.RequestRate.DeviationScore(currentRate)
	severity := params.detectorSeverity("rate_anomaly", "medium")
	if score > 0.8 {
		severity = "high"
	}

	return &AnomalyFinding{
		Type:     "rate_anomaly",
		Severity: severity,
		Reason:   fmt.Sprintf("request rate %.1f/min exceeds baseline mean %.1f (stddev: %.1f, sigmas: %.1f)", currentRate, baseline.RequestRate.Mean(), baseline.RequestRate.StdDev(), sigmas),
		Score:    score,
		Baseline: map[string]float64{
			"mean":   baseline.RequestRate.Mean(),
			"stddev": baseline.RequestRate.StdDev(),
		},
		Current: map[string]float64{
			"rate": currentRate,
		},
	}
}

// detectPayloadEntropy analyzes Shannon entropy of request payload.
func detectPayloadEntropy(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || ctx.FiberCtx == nil {
		return nil
	}

	body := ctx.FiberCtx.Body()
	queryStr := ctx.FiberCtx.Request().URI().QueryString()

	var data []byte
	if len(body) > 0 {
		data = body
	} else if len(queryStr) > 0 {
		data = queryStr
	}

	if len(data) < 16 {
		return nil
	}

	// Cap scan size.
	if len(data) > 64*1024 {
		data = data[:64*1024]
	}

	entropy := shannonEntropy(data)

	highThreshold := params.threshold("payload_entropy", "high", 4.5)
	lowThreshold := params.threshold("payload_entropy", "low", 1.0)

	severity := params.detectorSeverity("payload_entropy", "medium")

	if entropy > highThreshold {
		score := (entropy - highThreshold) / (8.0 - highThreshold) // normalize against max entropy (8 bits)
		if score > 1.0 {
			score = 1.0
		}
		return &AnomalyFinding{
			Type:     "payload_entropy",
			Severity: severity,
			Reason:   fmt.Sprintf("high payload entropy %.2f exceeds threshold %.2f (possible encoded/encrypted exfiltration)", entropy, highThreshold),
			Score:    score,
			Current: map[string]float64{
				"entropy":   entropy,
				"threshold": highThreshold,
			},
		}
	}

	if entropy < lowThreshold && baseline != nil && baseline.PayloadSize.Count > 5 {
		// Low entropy on endpoint that normally has varied content.
		score := (lowThreshold - entropy) / lowThreshold
		if score > 1.0 {
			score = 1.0
		}
		return &AnomalyFinding{
			Type:     "payload_entropy",
			Severity: "low",
			Reason:   fmt.Sprintf("very low payload entropy %.2f below threshold %.2f (possible automated replay)", entropy, lowThreshold),
			Score:    score,
			Current: map[string]float64{
				"entropy":   entropy,
				"threshold": lowThreshold,
			},
		}
	}

	return nil
}

// detectGeoAnomaly detects impossible travel based on geo changes.
func detectGeoAnomaly(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || ctx.RuleEngine == nil || ctx.FiberCtx == nil || baseline == nil {
		return nil
	}

	clientIP := ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	if clientIP == "" {
		return nil
	}

	currentCountry := ctx.RuleEngine.GetCountryFromIP(clientIP, "")
	if currentCountry == "" {
		return nil
	}

	severity := params.detectorSeverity("geo_anomaly", "high")
	windowMinutes := params.threshold("geo_anomaly", "windowMinutes", 60)

	if baseline.LastCountry != "" && baseline.LastCountry != currentCountry {
		elapsed := time.Since(baseline.LastGeoTime)
		if elapsed.Minutes() < windowMinutes && elapsed > 0 {
			// Different countries in short timeframe → impossible travel.
			score := 1.0 - (elapsed.Minutes() / windowMinutes)
			if score < 0.5 {
				score = 0.5
			}
			if score > 1.0 {
				score = 1.0
			}

			finding := &AnomalyFinding{
				Type:     "geo_anomaly",
				Severity: severity,
				Reason:   fmt.Sprintf("impossible travel: country changed from %s to %s in %s", baseline.LastCountry, currentCountry, elapsed.Round(time.Second)),
				Score:    score,
				Baseline: map[string]float64{
					"windowMinutes": windowMinutes,
				},
				Current: map[string]float64{
					"elapsedMinutes": elapsed.Minutes(),
				},
			}

			// Update baseline.
			baseline.LastCountry = currentCountry
			baseline.LastGeoTime = time.Now()

			return finding
		}
	}

	// Update baseline.
	baseline.LastCountry = currentCountry
	baseline.LastGeoTime = time.Now()

	return nil
}

// detectTemporalAnomaly checks if access is at an unusual hour for this IP.
func detectTemporalAnomaly(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || baseline == nil {
		return nil
	}

	minHistory := int(params.threshold("temporal_anomaly", "minHistoryHours", 50))
	rarityThreshold := params.threshold("temporal_anomaly", "rarityThreshold", 0.05)

	// Check if we have enough history.
	totalAccess := 0
	for _, count := range baseline.HourHistogram {
		totalAccess += count
	}
	if totalAccess < minHistory {
		return nil
	}

	currentHour := time.Now().Hour()
	hourCount := baseline.HourHistogram[currentHour]
	frequency := float64(hourCount) / float64(totalAccess)

	if frequency >= rarityThreshold {
		return nil
	}

	severity := params.detectorSeverity("temporal_anomaly", "medium")
	score := (rarityThreshold - frequency) / rarityThreshold
	if score > 1.0 {
		score = 1.0
	}

	return &AnomalyFinding{
		Type:     "temporal_anomaly",
		Severity: severity,
		Reason:   fmt.Sprintf("access at unusual hour %d:00 (frequency: %.3f, threshold: %.3f)", currentHour, frequency, rarityThreshold),
		Score:    score,
		Baseline: map[string]float64{
			"totalSamples":    float64(totalAccess),
			"hourFrequency":   frequency,
			"rarityThreshold": rarityThreshold,
		},
		Current: map[string]float64{
			"hour":      float64(currentHour),
			"hourCount": float64(hourCount),
		},
	}
}

// detectBehavioralDrift compares recent behavior fingerprint against baseline.
func detectBehavioralDrift(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || ctx.FiberCtx == nil || baseline == nil {
		return nil
	}

	driftThreshold := params.threshold("behavioral_drift", "driftThreshold", 0.3)
	minPaths := int(params.threshold("behavioral_drift", "baselinePaths", 5))

	if len(baseline.PathHistory) < minPaths {
		return nil
	}

	// Build current request fingerprint.
	currentPath := ctx.FiberCtx.Path()
	currentMethod := ctx.FiberCtx.Method()
	currentUA := ctx.FiberCtx.Get("User-Agent")

	// Jaccard similarity for paths.
	currentPaths := map[string]bool{currentPath: true}
	baselinePaths := make(map[string]bool, len(baseline.PathHistory))
	for p := range baseline.PathHistory {
		baselinePaths[p] = true
	}
	pathSimilarity := anomalyJaccardSimilarity(currentPaths, baselinePaths)

	// Method check.
	methodKnown := baseline.MethodHistory[currentMethod] > 0
	methodScore := 0.0
	if !methodKnown && len(baseline.MethodHistory) > 0 {
		methodScore = 0.5
	}

	// UA check.
	uaKnown := baseline.UAHistory[currentUA] > 0
	uaScore := 0.0
	if !uaKnown && len(baseline.UAHistory) > 0 {
		uaScore = 0.3
	}

	// Composite drift score.
	driftScore := (1.0-pathSimilarity)*0.5 + methodScore*0.25 + uaScore*0.25

	if driftScore < driftThreshold {
		return nil
	}

	severity := params.detectorSeverity("behavioral_drift", "medium")
	if driftScore > 0.7 {
		severity = "high"
	}

	return &AnomalyFinding{
		Type:     "behavioral_drift",
		Severity: severity,
		Reason:   fmt.Sprintf("behavioral drift detected (score: %.2f, threshold: %.2f): path similarity=%.2f, method_known=%v, ua_known=%v", driftScore, driftThreshold, pathSimilarity, methodKnown, uaKnown),
		Score:    driftScore,
		Baseline: map[string]float64{
			"knownPaths":     float64(len(baseline.PathHistory)),
			"knownMethods":   float64(len(baseline.MethodHistory)),
			"knownUAs":       float64(len(baseline.UAHistory)),
			"driftThreshold": driftThreshold,
		},
		Current: map[string]float64{
			"pathSimilarity": pathSimilarity,
			"methodScore":    methodScore,
			"uaScore":        uaScore,
			"driftScore":     driftScore,
		},
	}
}

// detectErrorRateAnomaly tracks and flags abnormal error rates per IP.
func detectErrorRateAnomaly(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || baseline == nil {
		return nil
	}

	errorRateThreshold := params.threshold("error_rate_anomaly", "errorRateThreshold", 0.5)
	minRequests := int(params.threshold("error_rate_anomaly", "minRequests", 20))

	if baseline.SampleCount < minRequests {
		return nil
	}

	if baseline.ErrorRate.Count < minRequests {
		return nil
	}

	currentErrorRate := baseline.ErrorRate.Mean()
	if currentErrorRate < errorRateThreshold {
		return nil
	}

	severity := params.detectorSeverity("error_rate_anomaly", "medium")
	score := currentErrorRate // error rate naturally 0-1
	if score > 1.0 {
		score = 1.0
	}

	return &AnomalyFinding{
		Type:     "error_rate_anomaly",
		Severity: severity,
		Reason:   fmt.Sprintf("high error rate %.2f exceeds threshold %.2f (from %d requests)", currentErrorRate, errorRateThreshold, baseline.ErrorRate.Count),
		Score:    score,
		Baseline: map[string]float64{
			"sampleCount": float64(baseline.ErrorRate.Count),
			"threshold":   errorRateThreshold,
		},
		Current: map[string]float64{
			"errorRate": currentErrorRate,
		},
	}
}

// detectResponseAnomaly flags response sizes that deviate significantly from baseline.
func detectResponseAnomaly(ctx *Context, baseline *IPBaseline, params *anomalyRuleParams) *AnomalyFinding {
	if ctx == nil || baseline == nil {
		return nil
	}

	sigmas := params.threshold("response_anomaly", "deviationSigmas", 3.0) * params.sensitivityMultiplier()
	minSamples := params.minSamplesOrDefault()

	if baseline.ResponseSize.Count < minSamples {
		return nil
	}

	// We need the response size from a previous request context;
	// check if it's available from telemetry.
	responseSize := 0.0
	if ctx.RuleEngine != nil && ctx.RuleEngine.telemetryStore != nil {
		clientIP := ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
		if extra := ctx.RuleEngine.telemetryStore.Snapshot(clientIP); len(extra) > 0 {
			if v, ok := extra["response_size"]; ok {
				responseSize = v
			}
		}
	}

	if responseSize <= 0 {
		return nil
	}

	if !baseline.ResponseSize.IsAnomaly(responseSize, sigmas) {
		return nil
	}

	severity := params.detectorSeverity("response_anomaly", "medium")
	score := baseline.ResponseSize.DeviationScore(responseSize)

	return &AnomalyFinding{
		Type:     "response_anomaly",
		Severity: severity,
		Reason:   fmt.Sprintf("response size %.0f bytes deviates from baseline mean %.0f (stddev: %.0f)", responseSize, baseline.ResponseSize.Mean(), baseline.ResponseSize.StdDev()),
		Score:    score,
		Baseline: map[string]float64{
			"mean":   baseline.ResponseSize.Mean(),
			"stddev": baseline.ResponseSize.StdDev(),
		},
		Current: map[string]float64{
			"responseSize": responseSize,
		},
	}
}

// ---------------------------------------------------------------------------
// Main pipeline function
// ---------------------------------------------------------------------------

// AnomalyDetectionCondition evaluates requests against statistical baselines
// and behavioral patterns. It follows the same pipeline function pattern as
// AdvancedDDoSCondition.
func AnomalyDetectionCondition(ctx *Context) any {
	if ctx == nil || ctx.RuleEngine == nil || ctx.FiberCtx == nil {
		return false
	}

	params, err := parseAnomalyRuleParams(ctx.Results)
	if err != nil {
		fmt.Printf("anomaly: failed to parse params: %v\n", err)
		return false
	}
	if params == nil {
		params = &anomalyRuleParams{}
	}

	tracker := getAnomalyTracker(ctx.RuleEngine)
	if tracker == nil {
		return false
	}

	clientIP := ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	if clientIP == "" {
		return false
	}

	baseline := tracker.GetOrCreate(params.baselineKey(clientIP, ctx.FiberCtx))

	var findings []AnomalyFinding

	// Run all enabled detectors.
	if params.isDetectorEnabled("rate_anomaly") {
		if finding := detectRateAnomaly(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if params.isDetectorEnabled("payload_entropy") {
		if finding := detectPayloadEntropy(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if params.isDetectorEnabled("geo_anomaly") {
		if finding := detectGeoAnomaly(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if params.isDetectorEnabled("temporal_anomaly") {
		if finding := detectTemporalAnomaly(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if params.isDetectorEnabled("behavioral_drift") {
		if finding := detectBehavioralDrift(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if params.isDetectorEnabled("error_rate_anomaly") {
		if finding := detectErrorRateAnomaly(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if params.isDetectorEnabled("response_anomaly") {
		if finding := detectResponseAnomaly(ctx, baseline, params); finding != nil {
			findings = append(findings, *finding)
		}
	}

	// Update baseline with current request.
	updateIPBaseline(ctx, baseline)

	// Compute aggregate score (max of findings).
	var maxScore float64
	for _, f := range findings {
		if f.Score > maxScore {
			maxScore = f.Score
		}
	}

	verdict := AnomalyDetectionVerdict{
		Triggered:    len(findings) > 0,
		Findings:     findings,
		AnomalyScore: maxScore,
	}

	ctx.Results["anomalyVerdict"] = verdict

	// Emit metrics.
	if verdict.Triggered && ctx.RuleEngine.metrics != nil {
		for _, f := range verdict.Findings {
			ctx.RuleEngine.metrics.IncrementCounter("anomaly_detection_total", map[string]string{
				"type":     f.Type,
				"severity": f.Severity,
			})
		}
	}

	return verdict.Triggered
}

// updateIPBaseline updates the baseline with current request data.
func updateIPBaseline(ctx *Context, baseline *IPBaseline) {
	if ctx == nil || ctx.FiberCtx == nil || baseline == nil {
		return
	}

	now := time.Now()
	baseline.LastUpdate = now
	baseline.SampleCount++

	// Update request rate (approximate).
	count, _ := getGlobalRequestStats(ctx.FiberCtx)
	if count > 0 {
		baseline.RequestRate.Add(float64(count))
	}

	// Update payload size.
	bodySize := len(ctx.FiberCtx.Body())
	if bodySize > 0 {
		baseline.PayloadSize.Add(float64(bodySize))
	}

	// Update behavioral fingerprint.
	path := ctx.FiberCtx.Path()
	if path != "" {
		if baseline.PathHistory == nil {
			baseline.PathHistory = make(map[string]int)
		}
		baseline.PathHistory[path]++
		// Cap path history size.
		if len(baseline.PathHistory) > 500 {
			// Remove least frequent entries.
			for p, c := range baseline.PathHistory {
				if c <= 1 {
					delete(baseline.PathHistory, p)
				}
			}
		}
	}

	method := ctx.FiberCtx.Method()
	if method != "" {
		if baseline.MethodHistory == nil {
			baseline.MethodHistory = make(map[string]int)
		}
		baseline.MethodHistory[method]++
	}

	ua := ctx.FiberCtx.Get("User-Agent")
	if ua != "" {
		if baseline.UAHistory == nil {
			baseline.UAHistory = make(map[string]int)
		}
		baseline.UAHistory[ua]++
		// Cap UA history.
		if len(baseline.UAHistory) > 50 {
			for u, c := range baseline.UAHistory {
				if c <= 1 {
					delete(baseline.UAHistory, u)
				}
			}
		}
	}

	// Update hour histogram.
	baseline.HourHistogram[now.Hour()]++
}

// ---------------------------------------------------------------------------
// Signal provider for RiskScorer
// ---------------------------------------------------------------------------

// AnomalyScoreSignalProvider returns a SignalProvider that can be registered with RiskScorer.
func AnomalyScoreSignalProvider(re *RuleEngine) SignalProvider {
	return func(ctx context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
		if re == nil {
			return RiskSignal{Score: 0, Weight: 1.0, Source: "anomaly_detector"}, nil
		}

		tracker := getAnomalyTracker(re)
		if tracker == nil {
			return RiskSignal{Score: 0, Weight: 1.0, Source: "anomaly_detector"}, nil
		}

		ip := req.IP
		if ip == "" {
			ip = req.ClientIP
		}
		if ip == "" {
			return RiskSignal{Score: 0, Weight: 1.0, Source: "anomaly_detector"}, nil
		}

		baseline := tracker.Get(ip)
		if baseline == nil {
			return RiskSignal{Score: 0, Weight: 1.0, Source: "anomaly_detector"}, nil
		}

		// Quick signal based on request rate deviation.
		var score float64
		if baseline.RequestRate.Count >= 10 {
			score = baseline.RequestRate.DeviationScore(baseline.RequestRate.Mean() * 1.5)
		}

		var reason string
		if score > 0.3 {
			reason = fmt.Sprintf("anomaly baseline deviation detected for IP %s", ip)
		}

		return RiskSignal{
			Score:  score,
			Weight: 1.0,
			Reason: reason,
			Source: "anomaly_detector",
		}, nil
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseAnomalyRuleParams(results map[string]any) (*anomalyRuleParams, error) {
	if results == nil {
		return &anomalyRuleParams{}, nil
	}
	raw, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	var params anomalyRuleParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return &params, nil
}

// shannonEntropy calculates the Shannon entropy of a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// anomalyJaccardSimilarity computes Jaccard similarity between two sets.
func anomalyJaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	intersection := 0
	union := make(map[string]bool)

	for k := range a {
		union[k] = true
		if b[k] {
			intersection++
		}
	}
	for k := range b {
		union[k] = true
	}

	if len(union) == 0 {
		return 1.0
	}
	return float64(intersection) / float64(len(union))
}
