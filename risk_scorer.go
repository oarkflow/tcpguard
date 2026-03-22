package tcpguard

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Decision represents the outcome of a risk evaluation.
type Decision int

const (
	// Allow permits the request without restriction.
	Allow Decision = iota
	// Challenge requires additional verification (e.g., CAPTCHA, MFA).
	Challenge
	// Contain permits the request but applies throttling or monitoring.
	Contain
	// Deny blocks the request entirely.
	Deny
)

// String returns the human-readable name of the Decision.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Challenge:
		return "challenge"
	case Contain:
		return "contain"
	case Deny:
		return "deny"
	default:
		return "unknown"
	}
}

// RiskSignal represents a single signal contributing to a risk score.
type RiskSignal struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`  // 0.0 (safe) to 1.0 (dangerous)
	Weight float64 `json:"weight"` // Default weight if not overridden by config
	Reason string  `json:"reason,omitempty"`
	Source string  `json:"source,omitempty"`
}

// RiskVerdict is the final result of a risk evaluation.
type RiskVerdict struct {
	Score    float64      `json:"score"`
	Decision Decision     `json:"decision"`
	Signals  []RiskSignal `json:"signals"`
}

// RiskRequest contains the input data for a risk evaluation.
type RiskRequest struct {
	IP                string            `json:"ip"`
	ClientIP          string            `json:"client_ip"`
	UserID            string            `json:"userId,omitempty"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	UserAgent         string            `json:"userAgent"`
	DeviceFingerprint string            `json:"deviceFingerprint,omitempty"`
	DeviceID          string            `json:"device_id,omitempty"`
	RouteTier         int               `json:"routeTier"` // 0=public, 1=authenticated, 2=sensitive, 3=admin
	Headers           map[string]string `json:"headers,omitempty"`
}

// RiskScoringConfig holds configuration for the risk scoring engine.
type RiskScoringConfig struct {
	// Weights maps signal name to its weight override.
	Weights map[string]float64 `json:"weights,omitempty"`

	// Thresholds define the score boundaries for each decision.
	ChallengeThreshold float64 `json:"challengeThreshold"`
	ContainThreshold   float64 `json:"containThreshold"`
	DenyThreshold      float64 `json:"denyThreshold"`

	// RouteSensitivity maps endpoint patterns to sensitivity tiers.
	RouteSensitivity []RouteSensitivity `json:"routeSensitivity,omitempty"`

	// BruteForceWindow is the sliding window for brute-force detection.
	BruteForceWindow time.Duration `json:"bruteForceWindow,omitempty"`
	// BruteForceThreshold is the failed login count that yields max signal score.
	BruteForceThreshold int `json:"bruteForceThreshold,omitempty"`
}

// RouteSensitivity maps an endpoint pattern to a sensitivity tier.
type RouteSensitivity struct {
	Pattern string `json:"pattern"`
	Tier    int    `json:"tier"`
}

// SignalProvider is a function that evaluates a risk signal for a given request.
type SignalProvider func(ctx context.Context, req *RiskRequest, store StateStore) (RiskSignal, error)

// RiskScorer evaluates the aggregate risk of a request.
type RiskScorer interface {
	Evaluate(req RiskRequest) (RiskVerdict, error)
	RegisterSignalProvider(name string, provider SignalProvider)
}

// DefaultRiskScorer implements RiskScorer with pluggable signal providers.
type DefaultRiskScorer struct {
	mu        sync.RWMutex
	providers map[string]SignalProvider
	store     StateStore
	config    RiskScoringConfig
}

// NewDefaultRiskScorer creates a DefaultRiskScorer with five built-in signal providers.
func NewDefaultRiskScorer(store StateStore, config RiskScoringConfig) *DefaultRiskScorer {
	if config.ChallengeThreshold == 0 {
		config.ChallengeThreshold = 0.3
	}
	if config.ContainThreshold == 0 {
		config.ContainThreshold = 0.6
	}
	if config.DenyThreshold == 0 {
		config.DenyThreshold = 0.85
	}
	if config.BruteForceWindow == 0 {
		config.BruteForceWindow = 10 * time.Minute
	}
	if config.BruteForceThreshold == 0 {
		config.BruteForceThreshold = 5
	}

	rs := &DefaultRiskScorer{
		providers: make(map[string]SignalProvider),
		store:     store,
		config:    config,
	}

	rs.providers["bruteForce"] = rs.bruteForceSignal
	rs.providers["newDevice"] = rs.newDeviceSignal
	rs.providers["ipReputation"] = rs.ipReputationSignal
	rs.providers["privilegedRoute"] = rs.privilegedRouteSignal
	rs.providers["automation"] = rs.automationSignal

	return rs
}

// RegisterSignalProvider adds or replaces a named signal provider.
func (rs *DefaultRiskScorer) RegisterSignalProvider(name string, provider SignalProvider) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.providers[name] = provider
}

// Evaluate collects signals from all providers, computes a weighted score,
// and maps it to a Decision via configured thresholds.
func (rs *DefaultRiskScorer) Evaluate(req RiskRequest) (RiskVerdict, error) {
	rs.mu.RLock()
	providers := make(map[string]SignalProvider, len(rs.providers))
	for k, v := range rs.providers {
		providers[k] = v
	}
	rs.mu.RUnlock()

	ctx := context.Background()
	var signals []RiskSignal
	var weightedSum float64
	var totalWeight float64

	for name, provider := range providers {
		signal, err := provider(ctx, &req, rs.store)
		if err != nil {
			continue
		}
		signal.Name = name

		weight := signal.Weight
		if w, ok := rs.config.Weights[name]; ok {
			weight = w
		}
		if weight <= 0 {
			weight = 1.0
		}

		score := signal.Score
		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}
		signal.Score = score

		signals = append(signals, signal)
		weightedSum += score * weight
		totalWeight += weight
	}

	var finalScore float64
	if totalWeight > 0 {
		finalScore = weightedSum / totalWeight
	}

	decision := rs.scoreToDecision(finalScore)

	return RiskVerdict{
		Score:    finalScore,
		Decision: decision,
		Signals:  signals,
	}, nil
}

func (rs *DefaultRiskScorer) scoreToDecision(score float64) Decision {
	switch {
	case score >= rs.config.DenyThreshold:
		return Deny
	case score >= rs.config.ContainThreshold:
		return Contain
	case score >= rs.config.ChallengeThreshold:
		return Challenge
	default:
		return Allow
	}
}

// bruteForceSignal checks the sliding window count of failed logins for the IP.
func (rs *DefaultRiskScorer) bruteForceSignal(_ context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
	if store == nil {
		return RiskSignal{Score: 0, Weight: 1.5, Source: "brute_force_detector"}, nil
	}
	ip := req.IP
	if ip == "" {
		ip = req.ClientIP
	}
	key := "failed_login:" + ip
	count, err := store.SlidingCount(key, rs.config.BruteForceWindow)
	if err != nil {
		return RiskSignal{Weight: 1.5}, err
	}

	score := float64(count) / float64(rs.config.BruteForceThreshold)
	if score > 1.0 {
		score = 1.0
	}

	var reason string
	if count > 0 {
		reason = "failed login attempts detected"
	}

	return RiskSignal{
		Score:  score,
		Weight: 1.5,
		Reason: reason,
		Source: "brute_force_detector",
	}, nil
}

// newDeviceSignal checks whether the device fingerprint is known/trusted.
func (rs *DefaultRiskScorer) newDeviceSignal(_ context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
	fp := req.DeviceFingerprint
	if fp == "" {
		fp = req.DeviceID
	}
	if fp == "" {
		return RiskSignal{Score: 0.3, Weight: 1.0, Reason: "no device fingerprint provided", Source: "device_trust"}, nil
	}
	if store == nil {
		return RiskSignal{Score: 0.5, Weight: 1.0, Reason: "no state store available", Source: "device_trust"}, nil
	}

	trust, err := store.GetDeviceTrust(fp)
	if err != nil {
		return RiskSignal{Weight: 1.0}, err
	}

	if trust == nil {
		return RiskSignal{Score: 0.8, Weight: 1.0, Reason: "unknown device", Source: "device_trust"}, nil
	}

	score := 1.0 - trust.TrustLevel
	if score < 0 {
		score = 0
	}
	return RiskSignal{Score: score, Weight: 1.0, Reason: "known device", Source: "device_trust"}, nil
}

// ipReputationSignal checks whether the IP is currently banned.
func (rs *DefaultRiskScorer) ipReputationSignal(_ context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
	if store == nil {
		return RiskSignal{Score: 0, Weight: 2.0, Source: "ip_reputation"}, nil
	}
	ip := req.IP
	if ip == "" {
		ip = req.ClientIP
	}
	ban, err := store.GetBan(ip)
	if err != nil {
		return RiskSignal{Weight: 2.0}, err
	}

	if ban != nil {
		if ban.Permanent || time.Now().Before(ban.Until) {
			return RiskSignal{Score: 1.0, Weight: 2.0, Reason: "IP is banned: " + ban.Reason, Source: "ip_reputation"}, nil
		}
	}

	return RiskSignal{Score: 0, Weight: 2.0, Source: "ip_reputation"}, nil
}

// privilegedRouteSignal returns a score based on the route sensitivity tier.
func (rs *DefaultRiskScorer) privilegedRouteSignal(_ context.Context, req *RiskRequest, _ StateStore) (RiskSignal, error) {
	tier := req.RouteTier

	var score float64
	switch tier {
	case 0:
		score = 0
	case 1:
		score = 0.2
	case 2:
		score = 0.6
	case 3:
		score = 1.0
	default:
		if tier > 3 {
			score = 1.0
		}
	}

	var reason string
	if tier >= 2 {
		reason = "privileged route access"
	}

	return RiskSignal{Score: score, Weight: 0.8, Reason: reason, Source: "route_sensitivity"}, nil
}

// automationSignal checks for bot-like user-agent patterns.
func (rs *DefaultRiskScorer) automationSignal(_ context.Context, req *RiskRequest, _ StateStore) (RiskSignal, error) {
	ua := strings.ToLower(req.UserAgent)

	if ua == "" {
		return RiskSignal{Score: 0.7, Weight: 1.2, Reason: "empty user-agent", Source: "automation_detector"}, nil
	}

	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget", "httpie",
		"python-requests", "go-http-client", "java/", "apache-httpclient",
		"node-fetch", "axios", "postman", "insomnia",
	}

	for _, pattern := range botPatterns {
		if strings.Contains(ua, pattern) {
			return RiskSignal{Score: 0.6, Weight: 1.2, Reason: "bot-like user-agent: " + pattern, Source: "automation_detector"}, nil
		}
	}

	return RiskSignal{Score: 0, Weight: 1.2, Source: "automation_detector"}, nil
}
