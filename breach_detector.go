package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// BreachFinding represents a single breach detection result.
type BreachFinding struct {
	Type       string         `json:"type"`       // data_exfiltration, privilege_escalation, lateral_movement, credential_stuffing, account_takeover, insider_threat
	Severity   string         `json:"severity"`
	Reason     string         `json:"reason"`
	Confidence float64        `json:"confidence"` // 0.0 - 1.0
	Indicators map[string]any `json:"indicators,omitempty"`
}

// BreachDetectionVerdict contains all breach detections for a request evaluation.
type BreachDetectionVerdict struct {
	Triggered bool            `json:"triggered"`
	Findings  []BreachFinding `json:"findings"`
}

// breachRuleParams holds JSON-configurable parameters for breach detection.
type breachRuleParams struct {
	Detectors           map[string]BreachDetectorConfig `json:"detectors"`
	DataExfiltration    DataExfiltrationConfig          `json:"dataExfiltration"`
	CredentialStuffing  CredentialStuffingConfig         `json:"credentialStuffing"`
	AccountTakeover     AccountTakeoverConfig            `json:"accountTakeover"`
	LateralMovement     LateralMovementConfig            `json:"lateralMovement"`
	PrivilegeEscalation PrivilegeEscalationConfig        `json:"privilegeEscalation"`
	InsiderThreat       InsiderThreatConfig              `json:"insiderThreat"`
}

// BreachDetectorConfig allows per-detector enable/disable/severity.
type BreachDetectorConfig struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// DataExfiltrationConfig configures data exfiltration detection.
type DataExfiltrationConfig struct {
	MaxResponseBytes    int64  `json:"maxResponseBytes"`    // cumulative threshold
	Window              string `json:"window"`
	BulkAccessThreshold int    `json:"bulkAccessThreshold"` // distinct endpoints in window
}

// CredentialStuffingConfig configures credential stuffing detection.
type CredentialStuffingConfig struct {
	Window              string  `json:"window"`
	MaxFailedLogins     int     `json:"maxFailedLogins"`
	UniqueUsernameRatio float64 `json:"uniqueUsernameRatio"` // spray detection threshold
	MinAttempts         int     `json:"minAttempts"`
}

// AccountTakeoverConfig configures account takeover detection.
type AccountTakeoverConfig struct {
	FailureThreshold int    `json:"failureThreshold"`
	GeoVelocityKmh   int    `json:"geoVelocityKmh"`
	MFARequired       bool   `json:"mfaRequired"`
	Window            string `json:"window"`
}

// LateralMovementConfig configures lateral movement detection.
type LateralMovementConfig struct {
	MaxAccountsPerIP int    `json:"maxAccountsPerIP"`
	MaxIPsPerUser    int    `json:"maxIPsPerUser"`
	Window           string `json:"window"`
}

// PrivilegeEscalationConfig configures privilege escalation detection.
type PrivilegeEscalationConfig struct {
	SensitiveEndpoints []string `json:"sensitiveEndpoints"`
	EscalationWindow   string   `json:"escalationWindow"`
	Max403Before200    int      `json:"max403Before200"`
}

// InsiderThreatConfig configures insider threat detection.
type InsiderThreatConfig struct {
	NormalHoursStart int      `json:"normalHoursStart"` // 0-23
	NormalHoursEnd   int      `json:"normalHoursEnd"`   // 0-23
	BulkThreshold    int      `json:"bulkThreshold"`
	ScopePatterns    []string `json:"scopePatterns"`
	Window           string   `json:"window"`
}

// ---------------------------------------------------------------------------
// Default config helpers
// ---------------------------------------------------------------------------

func (p *breachRuleParams) isDetectorEnabled(name string) bool {
	if p == nil || p.Detectors == nil {
		return true // all enabled by default
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

func (p *breachRuleParams) detectorSeverity(name, fallback string) string {
	if p == nil || p.Detectors == nil {
		return fallback
	}
	cfg, ok := p.Detectors[name]
	if !ok || cfg.Severity == "" {
		return fallback
	}
	return cfg.Severity
}

func (p *breachRuleParams) exfiltrationDefaults() DataExfiltrationConfig {
	cfg := p.DataExfiltration
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 50 * 1024 * 1024 // 50MB
	}
	if cfg.Window == "" {
		cfg.Window = "10m"
	}
	if cfg.BulkAccessThreshold <= 0 {
		cfg.BulkAccessThreshold = 30
	}
	return cfg
}

func (p *breachRuleParams) credentialStuffingDefaults() CredentialStuffingConfig {
	cfg := p.CredentialStuffing
	if cfg.Window == "" {
		cfg.Window = "10m"
	}
	if cfg.MaxFailedLogins <= 0 {
		cfg.MaxFailedLogins = 20
	}
	if cfg.UniqueUsernameRatio <= 0 {
		cfg.UniqueUsernameRatio = 0.8
	}
	if cfg.MinAttempts <= 0 {
		cfg.MinAttempts = 5
	}
	return cfg
}

func (p *breachRuleParams) accountTakeoverDefaults() AccountTakeoverConfig {
	cfg := p.AccountTakeover
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.GeoVelocityKmh <= 0 {
		cfg.GeoVelocityKmh = 900
	}
	if cfg.Window == "" {
		cfg.Window = "15m"
	}
	return cfg
}

func (p *breachRuleParams) lateralMovementDefaults() LateralMovementConfig {
	cfg := p.LateralMovement
	if cfg.MaxAccountsPerIP <= 0 {
		cfg.MaxAccountsPerIP = 3
	}
	if cfg.MaxIPsPerUser <= 0 {
		cfg.MaxIPsPerUser = 5
	}
	if cfg.Window == "" {
		cfg.Window = "15m"
	}
	return cfg
}

func (p *breachRuleParams) privilegeEscalationDefaults() PrivilegeEscalationConfig {
	cfg := p.PrivilegeEscalation
	if len(cfg.SensitiveEndpoints) == 0 {
		cfg.SensitiveEndpoints = []string{"/admin", "/api/admin", "/api/users", "/api/config", "/settings"}
	}
	if cfg.EscalationWindow == "" {
		cfg.EscalationWindow = "10m"
	}
	if cfg.Max403Before200 <= 0 {
		cfg.Max403Before200 = 3
	}
	return cfg
}

func (p *breachRuleParams) insiderThreatDefaults() InsiderThreatConfig {
	cfg := p.InsiderThreat
	if cfg.NormalHoursStart == 0 && cfg.NormalHoursEnd == 0 {
		cfg.NormalHoursStart = 6
		cfg.NormalHoursEnd = 22
	}
	if cfg.BulkThreshold <= 0 {
		cfg.BulkThreshold = 100
	}
	if cfg.Window == "" {
		cfg.Window = "15m"
	}
	return cfg
}

// ---------------------------------------------------------------------------
// State tracking
// ---------------------------------------------------------------------------

type responseStats struct {
	mu          sync.Mutex
	totalBytes  int64
	requestCount int
	endpoints   map[string]int
	firstSeen   time.Time
	lastSeen    time.Time
}

type loginStats struct {
	mu              sync.Mutex
	totalAttempts   int
	failedAttempts  int
	usernames       map[string]int
	firstAttempt    time.Time
	lastAttempt     time.Time
	lastSuccess     *time.Time
	lastSuccessUser string
}

type accessPattern struct {
	mu            sync.Mutex
	endpoints     map[string]int
	statusCodes   map[string][]int // endpoint -> list of status codes
	hourlyAccess  [24]int
	totalRequests int
	firstAccess   time.Time
	lastAccess    time.Time
}

// BreachDetectorState tracks state for breach detection across requests.
type BreachDetectorState struct {
	mu              sync.RWMutex
	responseTracker map[string]*responseStats    // IP -> cumulative response tracking
	loginTracker    map[string]*loginStats       // IP -> login attempt tracking
	userIPMapping   map[string]map[string]time.Time // user -> IP -> last seen
	ipUserMapping   map[string]map[string]time.Time // IP -> user -> last seen
	accessPatterns  map[string]*accessPattern    // user -> access pattern tracking

	maxAge      time.Duration
	stopCleanup chan struct{}
	stopped     sync.Once
}

// NewBreachDetectorState creates a new BreachDetectorState with cleanup.
func NewBreachDetectorState() *BreachDetectorState {
	s := &BreachDetectorState{
		responseTracker: make(map[string]*responseStats),
		loginTracker:    make(map[string]*loginStats),
		userIPMapping:   make(map[string]map[string]time.Time),
		ipUserMapping:   make(map[string]map[string]time.Time),
		accessPatterns:  make(map[string]*accessPattern),
		maxAge:          30 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}
	go s.startCleanup()
	return s
}

func (s *BreachDetectorState) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

func (s *BreachDetectorState) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-s.maxAge)

	for ip, stats := range s.responseTracker {
		stats.mu.Lock()
		if stats.lastSeen.Before(cutoff) {
			delete(s.responseTracker, ip)
		}
		stats.mu.Unlock()
	}

	for ip, stats := range s.loginTracker {
		stats.mu.Lock()
		if stats.lastAttempt.Before(cutoff) {
			delete(s.loginTracker, ip)
		}
		stats.mu.Unlock()
	}

	for user, ips := range s.userIPMapping {
		for ip, lastSeen := range ips {
			if lastSeen.Before(cutoff) {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(s.userIPMapping, user)
		}
	}

	for ip, users := range s.ipUserMapping {
		for user, lastSeen := range users {
			if lastSeen.Before(cutoff) {
				delete(users, user)
			}
		}
		if len(users) == 0 {
			delete(s.ipUserMapping, ip)
		}
	}

	for user, pattern := range s.accessPatterns {
		pattern.mu.Lock()
		if pattern.lastAccess.Before(cutoff) {
			delete(s.accessPatterns, user)
		}
		pattern.mu.Unlock()
	}
}

// StopCleanup stops the background cleanup goroutine.
func (s *BreachDetectorState) StopCleanup() {
	s.stopped.Do(func() {
		close(s.stopCleanup)
	})
}

// TrackResponse records response data for an IP.
func (s *BreachDetectorState) TrackResponse(ip string, responseBytes int64, endpoint string) {
	s.mu.RLock()
	stats := s.responseTracker[ip]
	s.mu.RUnlock()

	if stats == nil {
		s.mu.Lock()
		stats = s.responseTracker[ip]
		if stats == nil {
			stats = &responseStats{
				endpoints: make(map[string]int),
				firstSeen: time.Now(),
			}
			s.responseTracker[ip] = stats
		}
		s.mu.Unlock()
	}

	stats.mu.Lock()
	stats.totalBytes += responseBytes
	stats.requestCount++
	stats.endpoints[endpoint]++
	stats.lastSeen = time.Now()
	stats.mu.Unlock()
}

// GetResponseStats returns response stats for an IP.
func (s *BreachDetectorState) GetResponseStats(ip string) *responseStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.responseTracker[ip]
}

// TrackLogin records a login attempt for an IP.
func (s *BreachDetectorState) TrackLogin(ip, username string, success bool) {
	s.mu.RLock()
	stats := s.loginTracker[ip]
	s.mu.RUnlock()

	if stats == nil {
		s.mu.Lock()
		stats = s.loginTracker[ip]
		if stats == nil {
			stats = &loginStats{
				usernames:    make(map[string]int),
				firstAttempt: time.Now(),
			}
			s.loginTracker[ip] = stats
		}
		s.mu.Unlock()
	}

	stats.mu.Lock()
	stats.totalAttempts++
	stats.lastAttempt = time.Now()
	stats.usernames[username]++
	if !success {
		stats.failedAttempts++
	} else {
		now := time.Now()
		stats.lastSuccess = &now
		stats.lastSuccessUser = username
	}
	stats.mu.Unlock()
}

// GetLoginStats returns login stats for an IP.
func (s *BreachDetectorState) GetLoginStats(ip string) *loginStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loginTracker[ip]
}

// TrackUserIP records a user-IP mapping.
func (s *BreachDetectorState) TrackUserIP(userID, ip string) {
	if userID == "" || ip == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.userIPMapping[userID] == nil {
		s.userIPMapping[userID] = make(map[string]time.Time)
	}
	s.userIPMapping[userID][ip] = now

	if s.ipUserMapping[ip] == nil {
		s.ipUserMapping[ip] = make(map[string]time.Time)
	}
	s.ipUserMapping[ip][userID] = now
}

// GetUsersForIP returns users that accessed from an IP within the window.
func (s *BreachDetectorState) GetUsersForIP(ip string, window time.Duration) map[string]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-window)
	result := make(map[string]time.Time)
	for user, lastSeen := range s.ipUserMapping[ip] {
		if lastSeen.After(cutoff) {
			result[user] = lastSeen
		}
	}
	return result
}

// GetIPsForUser returns IPs that a user accessed from within the window.
func (s *BreachDetectorState) GetIPsForUser(userID string, window time.Duration) map[string]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-window)
	result := make(map[string]time.Time)
	for ip, lastSeen := range s.userIPMapping[userID] {
		if lastSeen.After(cutoff) {
			result[ip] = lastSeen
		}
	}
	return result
}

// TrackAccess records an endpoint access for a user.
func (s *BreachDetectorState) TrackAccess(userID, endpoint string, statusCode int) {
	if userID == "" {
		return
	}
	s.mu.RLock()
	pattern := s.accessPatterns[userID]
	s.mu.RUnlock()

	if pattern == nil {
		s.mu.Lock()
		pattern = s.accessPatterns[userID]
		if pattern == nil {
			pattern = &accessPattern{
				endpoints:   make(map[string]int),
				statusCodes: make(map[string][]int),
				firstAccess: time.Now(),
			}
			s.accessPatterns[userID] = pattern
		}
		s.mu.Unlock()
	}

	pattern.mu.Lock()
	pattern.endpoints[endpoint]++
	pattern.totalRequests++
	pattern.lastAccess = time.Now()
	pattern.hourlyAccess[time.Now().Hour()]++
	if statusCode > 0 {
		codes := pattern.statusCodes[endpoint]
		if len(codes) < 100 { // cap to prevent unbounded growth
			pattern.statusCodes[endpoint] = append(codes, statusCode)
		}
	}
	pattern.mu.Unlock()
}

// GetAccessPattern returns the access pattern for a user.
func (s *BreachDetectorState) GetAccessPattern(userID string) *accessPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessPatterns[userID]
}

// ---------------------------------------------------------------------------
// Detection functions
// ---------------------------------------------------------------------------

// detectDataExfiltration checks for data exfiltration patterns.
func detectDataExfiltration(ctx *Context, state *BreachDetectorState, params *breachRuleParams, store StateStore) []BreachFinding {
	if ctx == nil || ctx.FiberCtx == nil || state == nil {
		return nil
	}

	cfg := params.exfiltrationDefaults()
	window := breachParseWindowDuration(cfg.Window, 10*time.Minute)
	severity := params.detectorSeverity("dataExfiltration", "high")
	clientIP := ""
	if ctx.RuleEngine != nil {
		clientIP = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}
	if clientIP == "" {
		return nil
	}

	var findings []BreachFinding

	stats := state.GetResponseStats(clientIP)
	if stats != nil {
		stats.mu.Lock()
		totalBytes := stats.totalBytes
		endpoints := len(stats.endpoints)
		elapsed := time.Since(stats.firstSeen)
		stats.mu.Unlock()

		if elapsed <= window {
			// Check cumulative response data.
			if totalBytes > cfg.MaxResponseBytes {
				confidence := breachClampConfidence(float64(totalBytes) / float64(cfg.MaxResponseBytes*2))
				if confidence < 0.6 {
					confidence = 0.6
				}
				findings = append(findings, BreachFinding{
					Type:       "data_exfiltration",
					Severity:   severity,
					Reason:     fmt.Sprintf("cumulative response data %d bytes exceeds threshold %d in %s from IP %s", totalBytes, cfg.MaxResponseBytes, cfg.Window, clientIP),
					Confidence: confidence,
					Indicators: map[string]any{
						"totalBytes":   totalBytes,
						"threshold":    cfg.MaxResponseBytes,
						"window":       cfg.Window,
						"clientIP":     clientIP,
						"endpointCount": endpoints,
					},
				})
			}

			// Check bulk endpoint access.
			if endpoints >= cfg.BulkAccessThreshold {
				confidence := breachClampConfidence(float64(endpoints) / float64(cfg.BulkAccessThreshold*2))
				if confidence < 0.5 {
					confidence = 0.5
				}
				findings = append(findings, BreachFinding{
					Type:       "data_exfiltration",
					Severity:   severity,
					Reason:     fmt.Sprintf("bulk API access: %d distinct endpoints hit from IP %s in %s (threshold: %d)", endpoints, clientIP, cfg.Window, cfg.BulkAccessThreshold),
					Confidence: confidence,
					Indicators: map[string]any{
						"endpointCount": endpoints,
						"threshold":     cfg.BulkAccessThreshold,
						"window":        cfg.Window,
						"clientIP":      clientIP,
					},
				})
			}
		}
	}

	// Also check via StateStore sliding window if available.
	if store != nil {
		exfilKey := fmt.Sprintf("breach:exfil:bytes:%s", clientIP)
		count, err := store.SlidingCount(exfilKey, window)
		if err == nil && int64(count) > cfg.MaxResponseBytes/(1024) {
			// Already captured above via in-memory tracker
			_ = count
		}
	}

	return findings
}

// detectCredentialStuffing checks for credential stuffing patterns.
func detectBreachCredentialStuffing(ctx *Context, state *BreachDetectorState, params *breachRuleParams, store StateStore) []BreachFinding {
	if ctx == nil || ctx.FiberCtx == nil || state == nil {
		return nil
	}

	cfg := params.credentialStuffingDefaults()
	severity := params.detectorSeverity("credentialStuffing", "critical")
	clientIP := ""
	if ctx.RuleEngine != nil {
		clientIP = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}
	if clientIP == "" {
		return nil
	}

	var findings []BreachFinding

	stats := state.GetLoginStats(clientIP)
	if stats == nil {
		return nil
	}

	stats.mu.Lock()
	totalAttempts := stats.totalAttempts
	failedAttempts := stats.failedAttempts
	uniqueUsernames := len(stats.usernames)
	stats.mu.Unlock()

	if totalAttempts < cfg.MinAttempts {
		return nil
	}

	// Check failed login threshold.
	if failedAttempts >= cfg.MaxFailedLogins {
		confidence := breachClampConfidence(float64(failedAttempts) / float64(cfg.MaxFailedLogins*2))
		if confidence < 0.7 {
			confidence = 0.7
		}
		findings = append(findings, BreachFinding{
			Type:       "credential_stuffing",
			Severity:   severity,
			Reason:     fmt.Sprintf("excessive failed logins from IP %s: %d failures (threshold: %d)", clientIP, failedAttempts, cfg.MaxFailedLogins),
			Confidence: confidence,
			Indicators: map[string]any{
				"failedAttempts":  failedAttempts,
				"threshold":       cfg.MaxFailedLogins,
				"totalAttempts":   totalAttempts,
				"uniqueUsernames": uniqueUsernames,
				"clientIP":        clientIP,
			},
		})
	}

	// Check unique username ratio (spray pattern).
	if totalAttempts >= cfg.MinAttempts && uniqueUsernames > 1 {
		ratio := float64(uniqueUsernames) / float64(totalAttempts)
		if ratio >= cfg.UniqueUsernameRatio {
			confidence := breachClampConfidence(ratio)
			findings = append(findings, BreachFinding{
				Type:       "credential_stuffing",
				Severity:   severity,
				Reason:     fmt.Sprintf("credential spray pattern from IP %s: %d unique usernames in %d attempts (ratio: %.2f)", clientIP, uniqueUsernames, totalAttempts, ratio),
				Confidence: confidence,
				Indicators: map[string]any{
					"uniqueUsernames":    uniqueUsernames,
					"totalAttempts":      totalAttempts,
					"ratio":              ratio,
					"thresholdRatio":     cfg.UniqueUsernameRatio,
					"clientIP":           clientIP,
				},
			})
		}
	}

	return findings
}

// detectAccountTakeover checks for account takeover patterns.
func detectAccountTakeover(ctx *Context, state *BreachDetectorState, params *breachRuleParams, store StateStore) []BreachFinding {
	if ctx == nil || ctx.FiberCtx == nil || state == nil {
		return nil
	}

	cfg := params.accountTakeoverDefaults()
	severity := params.detectorSeverity("accountTakeover", "critical")
	clientIP := ""
	if ctx.RuleEngine != nil {
		clientIP = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}
	if clientIP == "" {
		return nil
	}

	var findings []BreachFinding

	// Detection 1: Success after brute force.
	stats := state.GetLoginStats(clientIP)
	if stats != nil {
		stats.mu.Lock()
		failedAttempts := stats.failedAttempts
		lastSuccess := stats.lastSuccess
		lastSuccessUser := stats.lastSuccessUser
		stats.mu.Unlock()

		if lastSuccess != nil && failedAttempts >= cfg.FailureThreshold {
			confidence := breachClampConfidence(float64(failedAttempts) / float64(cfg.FailureThreshold*3))
			if confidence < 0.7 {
				confidence = 0.7
			}
			findings = append(findings, BreachFinding{
				Type:       "account_takeover",
				Severity:   severity,
				Reason:     fmt.Sprintf("successful login after %d failed attempts from IP %s for user %s", failedAttempts, clientIP, lastSuccessUser),
				Confidence: confidence,
				Indicators: map[string]any{
					"failedAttempts": failedAttempts,
					"threshold":      cfg.FailureThreshold,
					"clientIP":       clientIP,
					"user":           lastSuccessUser,
				},
			})
		}
	}

	// Detection 2: Impossible travel via session state.
	if store != nil {
		userID := ""
		if ctx.RuleEngine != nil {
			userID = ctx.RuleEngine.GetUserID(ctx.FiberCtx)
		}
		if userID != "" {
			sessionState, err := store.GetSessionState(userID)
			if err == nil && sessionState != nil && sessionState.IP != "" && sessionState.IP != clientIP {
				elapsed := time.Since(sessionState.LastActive)
				if elapsed < 30*time.Minute && elapsed > 0 {
					findings = append(findings, BreachFinding{
						Type:       "account_takeover",
						Severity:   severity,
						Reason:     fmt.Sprintf("session IP change for user %s: %s -> %s within %s", userID, sessionState.IP, clientIP, elapsed),
						Confidence: 0.7,
						Indicators: map[string]any{
							"userID":     userID,
							"previousIP": sessionState.IP,
							"currentIP":  clientIP,
							"elapsed":    elapsed.String(),
						},
					})
				}
			}
		}
	}

	// Detection 3: MFA bypass check.
	if cfg.MFARequired && store != nil {
		userID := ""
		if ctx.RuleEngine != nil {
			userID = ctx.RuleEngine.GetUserID(ctx.FiberCtx)
		}
		if userID != "" {
			sessionState, err := store.GetSessionState(userID)
			if err == nil && sessionState != nil && !sessionState.MFAVerified {
				findings = append(findings, BreachFinding{
					Type:       "account_takeover",
					Severity:   "high",
					Reason:     fmt.Sprintf("active session without MFA verification for user %s from IP %s", userID, clientIP),
					Confidence: 0.6,
					Indicators: map[string]any{
						"userID":   userID,
						"clientIP": clientIP,
						"mfaRequired": true,
					},
				})
			}
		}
	}

	return findings
}

// detectLateralMovement checks for lateral movement patterns.
func detectLateralMovement(ctx *Context, state *BreachDetectorState, params *breachRuleParams) []BreachFinding {
	if ctx == nil || ctx.FiberCtx == nil || state == nil {
		return nil
	}

	cfg := params.lateralMovementDefaults()
	window := breachParseWindowDuration(cfg.Window, 15*time.Minute)
	severity := params.detectorSeverity("lateralMovement", "high")
	clientIP := ""
	if ctx.RuleEngine != nil {
		clientIP = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}
	if clientIP == "" {
		return nil
	}

	var findings []BreachFinding

	// Detection 1: Single IP accessing multiple user accounts.
	usersForIP := state.GetUsersForIP(clientIP, window)
	if len(usersForIP) > cfg.MaxAccountsPerIP {
		confidence := breachClampConfidence(float64(len(usersForIP)) / float64(cfg.MaxAccountsPerIP*2))
		if confidence < 0.6 {
			confidence = 0.6
		}
		users := make([]string, 0, len(usersForIP))
		for u := range usersForIP {
			users = append(users, u)
		}
		findings = append(findings, BreachFinding{
			Type:       "lateral_movement",
			Severity:   severity,
			Reason:     fmt.Sprintf("single IP %s accessed %d different user accounts in %s (threshold: %d)", clientIP, len(usersForIP), cfg.Window, cfg.MaxAccountsPerIP),
			Confidence: confidence,
			Indicators: map[string]any{
				"clientIP":     clientIP,
				"accountCount": len(usersForIP),
				"threshold":    cfg.MaxAccountsPerIP,
				"window":       cfg.Window,
				"accounts":     users,
			},
		})
	}

	// Detection 2: Single user session from multiple IPs.
	userID := ""
	if ctx.RuleEngine != nil {
		userID = ctx.RuleEngine.GetUserID(ctx.FiberCtx)
	}
	if userID != "" {
		ipsForUser := state.GetIPsForUser(userID, window)
		if len(ipsForUser) > cfg.MaxIPsPerUser {
			confidence := breachClampConfidence(float64(len(ipsForUser)) / float64(cfg.MaxIPsPerUser*2))
			if confidence < 0.5 {
				confidence = 0.5
			}
			ips := make([]string, 0, len(ipsForUser))
			for ip := range ipsForUser {
				ips = append(ips, ip)
			}
			findings = append(findings, BreachFinding{
				Type:       "lateral_movement",
				Severity:   severity,
				Reason:     fmt.Sprintf("user %s accessed from %d different IPs in %s (threshold: %d)", userID, len(ipsForUser), cfg.Window, cfg.MaxIPsPerUser),
				Confidence: confidence,
				Indicators: map[string]any{
					"userID":    userID,
					"ipCount":   len(ipsForUser),
					"threshold": cfg.MaxIPsPerUser,
					"window":    cfg.Window,
					"ips":       ips,
				},
			})
		}
	}

	// Detection 3: Cross-account sensitive endpoint access.
	if len(usersForIP) > 1 {
		sensitiveEndpoints := params.privilegeEscalationDefaults().SensitiveEndpoints
		path := ctx.FiberCtx.Path()
		for _, sensitive := range sensitiveEndpoints {
			if strings.HasPrefix(path, sensitive) {
				findings = append(findings, BreachFinding{
					Type:       "lateral_movement",
					Severity:   "critical",
					Reason:     fmt.Sprintf("sensitive endpoint %s accessed from IP %s which has sessions for %d accounts", path, clientIP, len(usersForIP)),
					Confidence: 0.75,
					Indicators: map[string]any{
						"path":         path,
						"clientIP":     clientIP,
						"accountCount": len(usersForIP),
					},
				})
				break
			}
		}
	}

	return findings
}

// detectPrivilegeEscalation checks for privilege escalation patterns.
func detectPrivilegeEscalation(ctx *Context, state *BreachDetectorState, params *breachRuleParams, store StateStore) []BreachFinding {
	if ctx == nil || ctx.FiberCtx == nil || state == nil {
		return nil
	}

	cfg := params.privilegeEscalationDefaults()
	severity := params.detectorSeverity("privilegeEscalation", "critical")
	path := ctx.FiberCtx.Path()

	userID := ""
	clientIP := ""
	if ctx.RuleEngine != nil {
		userID = ctx.RuleEngine.GetUserID(ctx.FiberCtx)
		clientIP = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}

	var findings []BreachFinding

	// Detection 1: Direct access to sensitive endpoints without lower-privilege access.
	isSensitive := false
	for _, sensitive := range cfg.SensitiveEndpoints {
		if strings.HasPrefix(path, sensitive) {
			isSensitive = true
			break
		}
	}

	if isSensitive && userID != "" {
		pattern := state.GetAccessPattern(userID)
		if pattern != nil {
			pattern.mu.Lock()
			hasNonSensitiveAccess := false
			for ep := range pattern.endpoints {
				epSensitive := false
				for _, sensitive := range cfg.SensitiveEndpoints {
					if strings.HasPrefix(ep, sensitive) {
						epSensitive = true
						break
					}
				}
				if !epSensitive {
					hasNonSensitiveAccess = true
					break
				}
			}
			totalReqs := pattern.totalRequests
			pattern.mu.Unlock()

			if !hasNonSensitiveAccess && totalReqs <= 3 {
				findings = append(findings, BreachFinding{
					Type:       "privilege_escalation",
					Severity:   severity,
					Reason:     fmt.Sprintf("direct access to sensitive endpoint %s without prior lower-privilege activity for user %s", path, userID),
					Confidence: 0.7,
					Indicators: map[string]any{
						"path":          path,
						"userID":        userID,
						"totalRequests": totalReqs,
					},
				})
			}
		} else {
			// First request is to sensitive endpoint.
			findings = append(findings, BreachFinding{
				Type:       "privilege_escalation",
				Severity:   severity,
				Reason:     fmt.Sprintf("first request from user %s is to sensitive endpoint %s", userID, path),
				Confidence: 0.6,
				Indicators: map[string]any{
					"path":   path,
					"userID": userID,
				},
			})
		}
	}

	// Detection 2: Repeated 403 followed by 200.
	if userID != "" {
		pattern := state.GetAccessPattern(userID)
		if pattern != nil {
			pattern.mu.Lock()
			for ep, codes := range pattern.statusCodes {
				if len(codes) < 2 {
					continue
				}
				forbidden403Count := 0
				saw200After403 := false
				for _, code := range codes {
					if code == 403 {
						forbidden403Count++
					} else if code == 200 && forbidden403Count >= cfg.Max403Before200 {
						saw200After403 = true
						break
					}
				}
				if saw200After403 {
					findings = append(findings, BreachFinding{
						Type:       "privilege_escalation",
						Severity:   severity,
						Reason:     fmt.Sprintf("successful access (200) to %s after %d forbidden (403) attempts for user %s", ep, forbidden403Count, userID),
						Confidence: breachClampConfidence(float64(forbidden403Count) / float64(cfg.Max403Before200+3)),
						Indicators: map[string]any{
							"endpoint":     ep,
							"forbidden403": forbidden403Count,
							"threshold":    cfg.Max403Before200,
							"userID":       userID,
						},
					})
				}
			}
			pattern.mu.Unlock()
		}
	}

	// Detection 3: Via StateStore sliding window.
	if store != nil && clientIP != "" {
		escalationWindow := breachParseWindowDuration(cfg.EscalationWindow, 10*time.Minute)
		escKey := fmt.Sprintf("breach:privesc:403:%s", clientIP)
		forbiddenCount, err := store.SlidingCount(escKey, escalationWindow)
		if err == nil && forbiddenCount >= cfg.Max403Before200 {
			succKey := fmt.Sprintf("breach:privesc:200:%s", clientIP)
			successCount, err := store.SlidingCount(succKey, escalationWindow)
			if err == nil && successCount > 0 {
				alreadyFound := false
				for _, f := range findings {
					if strings.Contains(f.Reason, "forbidden (403)") {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					findings = append(findings, BreachFinding{
						Type:       "privilege_escalation",
						Severity:   severity,
						Reason:     fmt.Sprintf("sliding window: %d forbidden responses followed by %d successes from IP %s", forbiddenCount, successCount, clientIP),
						Confidence: 0.65,
						Indicators: map[string]any{
							"forbiddenCount": forbiddenCount,
							"successCount":   successCount,
							"clientIP":       clientIP,
						},
					})
				}
			}
		}
	}

	return findings
}

// detectInsiderThreat checks for insider threat patterns.
func detectInsiderThreat(ctx *Context, state *BreachDetectorState, params *breachRuleParams, store StateStore) []BreachFinding {
	if ctx == nil || ctx.FiberCtx == nil || state == nil {
		return nil
	}

	cfg := params.insiderThreatDefaults()
	severity := params.detectorSeverity("insiderThreat", "high")
	window := breachParseWindowDuration(cfg.Window, 15*time.Minute)

	userID := ""
	if ctx.RuleEngine != nil {
		userID = ctx.RuleEngine.GetUserID(ctx.FiberCtx)
	}
	if userID == "" {
		return nil // insider threat requires an authenticated user
	}

	var findings []BreachFinding

	// Detection 1: Access outside normal hours.
	now := time.Now()
	hour := now.Hour()
	outsideHours := false
	if cfg.NormalHoursStart < cfg.NormalHoursEnd {
		outsideHours = hour < cfg.NormalHoursStart || hour >= cfg.NormalHoursEnd
	} else {
		outsideHours = hour >= cfg.NormalHoursEnd && hour < cfg.NormalHoursStart
	}

	if outsideHours {
		pattern := state.GetAccessPattern(userID)
		isUnusual := true
		if pattern != nil {
			pattern.mu.Lock()
			if pattern.hourlyAccess[hour] > 5 {
				isUnusual = false
			}
			pattern.mu.Unlock()
		}
		if isUnusual {
			findings = append(findings, BreachFinding{
				Type:       "insider_threat",
				Severity:   "medium",
				Reason:     fmt.Sprintf("access outside normal hours (hour %d) for user %s (normal: %d:00-%d:00)", hour, userID, cfg.NormalHoursStart, cfg.NormalHoursEnd),
				Confidence: 0.5,
				Indicators: map[string]any{
					"currentHour":      hour,
					"normalHoursStart": cfg.NormalHoursStart,
					"normalHoursEnd":   cfg.NormalHoursEnd,
					"userID":           userID,
				},
			})
		}
	}

	// Detection 2: Bulk data access by authenticated user.
	if store != nil {
		bulkKey := fmt.Sprintf("breach:insider:bulk:%s", userID)
		count, err := store.SlidingCount(bulkKey, window)
		if err == nil && count >= cfg.BulkThreshold {
			findings = append(findings, BreachFinding{
				Type:       "insider_threat",
				Severity:   severity,
				Reason:     fmt.Sprintf("bulk data access: user %s made %d requests in %s (threshold: %d)", userID, count, cfg.Window, cfg.BulkThreshold),
				Confidence: breachClampConfidence(float64(count) / float64(cfg.BulkThreshold*2)),
				Indicators: map[string]any{
					"requestCount": count,
					"threshold":    cfg.BulkThreshold,
					"window":       cfg.Window,
					"userID":       userID,
				},
			})
		}
	}

	// Detection 2b: In-memory access pattern.
	pattern := state.GetAccessPattern(userID)
	if pattern != nil {
		pattern.mu.Lock()
		totalReqs := pattern.totalRequests
		numEndpoints := len(pattern.endpoints)
		elapsed := time.Since(pattern.firstAccess)
		pattern.mu.Unlock()

		if elapsed <= window && totalReqs >= cfg.BulkThreshold {
			alreadyFound := false
			for _, f := range findings {
				if strings.Contains(f.Reason, "bulk data access") {
					alreadyFound = true
					break
				}
			}
			if !alreadyFound {
				findings = append(findings, BreachFinding{
					Type:       "insider_threat",
					Severity:   severity,
					Reason:     fmt.Sprintf("bulk data access: user %s made %d requests across %d endpoints", userID, totalReqs, numEndpoints),
					Confidence: breachClampConfidence(float64(totalReqs) / float64(cfg.BulkThreshold*2)),
					Indicators: map[string]any{
						"requestCount":      totalReqs,
						"threshold":         cfg.BulkThreshold,
						"distinctEndpoints": numEndpoints,
						"userID":            userID,
					},
				})
			}
		}
	}

	// Detection 3: Access to resources outside normal scope.
	if len(cfg.ScopePatterns) > 0 {
		path := ctx.FiberCtx.Path()
		inScope := false
		for _, scopePattern := range cfg.ScopePatterns {
			if scopePattern == "" {
				continue
			}
			if strings.HasSuffix(scopePattern, "*") {
				prefix := strings.TrimSuffix(scopePattern, "*")
				if strings.HasPrefix(path, prefix) {
					inScope = true
					break
				}
			} else if path == scopePattern || strings.HasPrefix(path, scopePattern) {
				inScope = true
				break
			}
		}

		if !inScope {
			findings = append(findings, BreachFinding{
				Type:       "insider_threat",
				Severity:   "medium",
				Reason:     fmt.Sprintf("user %s accessed resource %s outside defined scope", userID, path),
				Confidence: 0.55,
				Indicators: map[string]any{
					"userID":        userID,
					"path":          path,
					"scopePatterns": cfg.ScopePatterns,
				},
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Main pipeline function
// ---------------------------------------------------------------------------

// BreachDetectionCondition is the main pipeline function for breach detection.
func BreachDetectionCondition(ctx *Context) any {
	if ctx == nil || ctx.RuleEngine == nil || ctx.FiberCtx == nil {
		return false
	}

	params, err := parseBreachRuleParams(ctx.Results)
	if err != nil {
		fmt.Printf("breach: failed to parse params: %v\n", err)
		return false
	}
	if params == nil {
		return false
	}

	state := getBreachDetectorState(ctx.RuleEngine)
	if state == nil {
		return false
	}

	// Get the StateStore if available.
	var store StateStore
	if ctx.RuleEngine.stateStore != nil {
		store = ctx.RuleEngine.stateStore
	}

	// Update tracking state with current request.
	clientIP := ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	userID := ctx.RuleEngine.GetUserID(ctx.FiberCtx)
	endpoint := ctx.FiberCtx.Path()

	if clientIP != "" && userID != "" {
		state.TrackUserIP(userID, clientIP)
	}
	if userID != "" {
		state.TrackAccess(userID, endpoint, 0)
	}

	verdict := BreachDetectionVerdict{}

	// Run all enabled detectors.
	if params.isDetectorEnabled("dataExfiltration") {
		findings := detectDataExfiltration(ctx, state, params, store)
		verdict.Findings = append(verdict.Findings, findings...)
	}

	if params.isDetectorEnabled("credentialStuffing") {
		findings := detectBreachCredentialStuffing(ctx, state, params, store)
		verdict.Findings = append(verdict.Findings, findings...)
	}

	if params.isDetectorEnabled("accountTakeover") {
		findings := detectAccountTakeover(ctx, state, params, store)
		verdict.Findings = append(verdict.Findings, findings...)
	}

	if params.isDetectorEnabled("lateralMovement") {
		findings := detectLateralMovement(ctx, state, params)
		verdict.Findings = append(verdict.Findings, findings...)
	}

	if params.isDetectorEnabled("privilegeEscalation") {
		findings := detectPrivilegeEscalation(ctx, state, params, store)
		verdict.Findings = append(verdict.Findings, findings...)
	}

	if params.isDetectorEnabled("insiderThreat") {
		findings := detectInsiderThreat(ctx, state, params, store)
		verdict.Findings = append(verdict.Findings, findings...)
	}

	verdict.Triggered = len(verdict.Findings) > 0

	// Store verdict in results.
	ctx.Results["breachVerdict"] = verdict

	// Emit SecurityEvents for high/critical findings.
	if verdict.Triggered && ctx.RuleEngine.eventEmitter != nil {
		for _, finding := range verdict.Findings {
			if finding.Severity == "high" || finding.Severity == "critical" {
				event := NewSecurityEvent("breach_"+finding.Type, finding.Severity)
				event.ClientIP = clientIP
				event.UserID = userID
				event.Path = endpoint
				event.Method = ctx.FiberCtx.Method()
				event.Decision = "alert"
				event.RiskScore = finding.Confidence
				event.Details = map[string]any{
					"findingType": finding.Type,
					"reason":      finding.Reason,
					"confidence":  finding.Confidence,
					"indicators":  finding.Indicators,
				}
				_ = ctx.RuleEngine.eventEmitter.Emit(context.Background(), event)
			}
		}
	}

	// Record metrics.
	if verdict.Triggered && ctx.RuleEngine.metrics != nil {
		for _, finding := range verdict.Findings {
			ctx.RuleEngine.metrics.IncrementCounter("breach_detection_total", map[string]string{
				"type":     finding.Type,
				"severity": finding.Severity,
			})
		}
	}

	return verdict.Triggered
}

// ---------------------------------------------------------------------------
// Signal providers for RiskScorer integration
// ---------------------------------------------------------------------------

// BreachExfiltrationSignal returns a SignalProvider for data exfiltration risk.
func BreachExfiltrationSignal(state *BreachDetectorState) SignalProvider {
	return func(ctx context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
		if state == nil {
			return RiskSignal{Score: 0, Weight: 1.5, Source: "breach_exfiltration"}, nil
		}
		ip := req.IP
		if ip == "" {
			ip = req.ClientIP
		}
		if ip == "" {
			return RiskSignal{Score: 0, Weight: 1.5, Source: "breach_exfiltration"}, nil
		}
		stats := state.GetResponseStats(ip)
		if stats == nil {
			return RiskSignal{Score: 0, Weight: 1.5, Source: "breach_exfiltration"}, nil
		}
		stats.mu.Lock()
		totalBytes := stats.totalBytes
		endpoints := len(stats.endpoints)
		stats.mu.Unlock()

		var score float64
		threshold := int64(50 * 1024 * 1024)
		if totalBytes > 0 {
			score = float64(totalBytes) / float64(threshold)
			if score > 1.0 {
				score = 1.0
			}
		}
		if endpoints > 20 {
			score += float64(endpoints) / 100.0
			if score > 1.0 {
				score = 1.0
			}
		}
		var reason string
		if score > 0.3 {
			reason = fmt.Sprintf("elevated data transfer: %d bytes across %d endpoints", totalBytes, endpoints)
		}
		return RiskSignal{Score: score, Weight: 1.5, Reason: reason, Source: "breach_exfiltration"}, nil
	}
}

// BreachCredentialStuffingSignal returns a SignalProvider for credential stuffing risk.
func BreachCredentialStuffingSignal(state *BreachDetectorState) SignalProvider {
	return func(ctx context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
		if state == nil {
			return RiskSignal{Score: 0, Weight: 2.0, Source: "breach_credential_stuffing"}, nil
		}
		ip := req.IP
		if ip == "" {
			ip = req.ClientIP
		}
		if ip == "" {
			return RiskSignal{Score: 0, Weight: 2.0, Source: "breach_credential_stuffing"}, nil
		}
		stats := state.GetLoginStats(ip)
		if stats == nil || stats.totalAttempts == 0 {
			return RiskSignal{Score: 0, Weight: 2.0, Source: "breach_credential_stuffing"}, nil
		}
		stats.mu.Lock()
		failedAttempts := stats.failedAttempts
		totalAttempts := stats.totalAttempts
		uniqueUsernames := len(stats.usernames)
		stats.mu.Unlock()

		var score float64
		if failedAttempts > 0 {
			score = float64(failedAttempts) / 20.0
			if score > 1.0 {
				score = 1.0
			}
		}
		if totalAttempts >= 5 && uniqueUsernames > 1 {
			ratio := float64(uniqueUsernames) / float64(totalAttempts)
			if ratio > 0.8 {
				score += ratio * 0.3
				if score > 1.0 {
					score = 1.0
				}
			}
		}
		var reason string
		if score > 0.3 {
			reason = fmt.Sprintf("credential stuffing indicators: %d failed/%d total, %d unique usernames", failedAttempts, totalAttempts, uniqueUsernames)
		}
		return RiskSignal{Score: score, Weight: 2.0, Reason: reason, Source: "breach_credential_stuffing"}, nil
	}
}

// BreachAccountTakeoverSignal returns a SignalProvider for account takeover risk.
func BreachAccountTakeoverSignal(state *BreachDetectorState) SignalProvider {
	return func(ctx context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
		if state == nil {
			return RiskSignal{Score: 0, Weight: 2.5, Source: "breach_account_takeover"}, nil
		}
		ip := req.IP
		if ip == "" {
			ip = req.ClientIP
		}
		if ip == "" {
			return RiskSignal{Score: 0, Weight: 2.5, Source: "breach_account_takeover"}, nil
		}
		var score float64
		stats := state.GetLoginStats(ip)
		if stats != nil {
			stats.mu.Lock()
			failedAttempts := stats.failedAttempts
			lastSuccess := stats.lastSuccess
			stats.mu.Unlock()

			if lastSuccess != nil && failedAttempts >= 5 {
				score = 0.8
			} else if failedAttempts > 0 {
				score = float64(failedAttempts) / 10.0
				if score > 0.6 {
					score = 0.6
				}
			}
		}
		if store != nil && req.UserID != "" {
			sessionState, err := store.GetSessionState(req.UserID)
			if err == nil && sessionState != nil && sessionState.IP != "" && sessionState.IP != ip {
				elapsed := time.Since(sessionState.LastActive)
				if elapsed < 30*time.Minute && elapsed > 0 {
					if score < 0.7 {
						score = 0.7
					}
				}
			}
		}
		if score > 1.0 {
			score = 1.0
		}
		var reason string
		if score > 0.3 {
			reason = "account takeover risk indicators detected"
		}
		return RiskSignal{Score: score, Weight: 2.5, Reason: reason, Source: "breach_account_takeover"}, nil
	}
}

// ---------------------------------------------------------------------------
// State management (package-level registry)
// ---------------------------------------------------------------------------

var (
	breachStateMu    sync.RWMutex
	breachStateStore = make(map[*RuleEngine]*BreachDetectorState)
)

func getBreachDetectorState(re *RuleEngine) *BreachDetectorState {
	if re == nil {
		return nil
	}
	breachStateMu.RLock()
	state := breachStateStore[re]
	breachStateMu.RUnlock()
	if state != nil {
		return state
	}

	breachStateMu.Lock()
	defer breachStateMu.Unlock()
	if state = breachStateStore[re]; state != nil {
		return state
	}
	state = NewBreachDetectorState()
	breachStateStore[re] = state
	return state
}

// RemoveBreachDetectorState cleans up the BreachDetectorState for a RuleEngine.
func RemoveBreachDetectorState(re *RuleEngine) {
	if re == nil {
		return
	}
	breachStateMu.Lock()
	defer breachStateMu.Unlock()
	if state, exists := breachStateStore[re]; exists {
		state.StopCleanup()
		delete(breachStateStore, re)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseBreachRuleParams(results map[string]any) (*breachRuleParams, error) {
	if results == nil {
		return &breachRuleParams{}, nil
	}
	raw, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	var params breachRuleParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return &params, nil
}

func breachParseWindowDuration(window string, fallback time.Duration) time.Duration {
	if window == "" {
		return fallback
	}
	d, err := time.ParseDuration(window)
	if err != nil {
		return fallback
	}
	return d
}

func breachClampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1.0 {
		return 1.0
	}
	return v
}
