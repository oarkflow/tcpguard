package tcpguard

import (
	"context"
	"sync"
	"time"
)

// LoginRiskRequest contains information about a login attempt for risk assessment.
type LoginRiskRequest struct {
	UserID      string    `json:"user_id"`
	DeviceID    string    `json:"device_id"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	GeoLocation string    `json:"geo_location"`
	Timestamp   time.Time `json:"timestamp"`
}

// LoginRiskVerdict is the result of a login risk assessment.
type LoginRiskVerdict struct {
	Score         float64  `json:"score"`
	Factors       []string `json:"factors"`
	AccountAction string   `json:"account_action"` // ""/"lockout"/"challenge"/"freeze"
	Confidence    float64  `json:"confidence"`
}

// LoginResult records the outcome of a login attempt.
type LoginResult struct {
	UserID      string    `json:"user_id"`
	ClientIP    string    `json:"client_ip"`
	DeviceID    string    `json:"device_id"`
	GeoLocation string    `json:"geo_location"`
	Success     bool      `json:"success"`
	Timestamp   time.Time `json:"timestamp"`
}

// IdentityRiskConfig holds configuration for identity risk assessment.
type IdentityRiskConfig struct {
	FailedLoginThreshold    int           `json:"failed_login_threshold"`
	FailedLoginWindow       time.Duration `json:"failed_login_window"`
	ImpossibleTravelSpeedKmH float64      `json:"impossible_travel_speed_kmh"`
	NewDeviceWeight         float64       `json:"new_device_weight"`
	FailedStreakWeight      float64       `json:"failed_streak_weight"`
}

// IdentityRiskAssessor assesses risk associated with identity and login events.
type IdentityRiskAssessor interface {
	AssessLogin(ctx context.Context, req *LoginRiskRequest) (*LoginRiskVerdict, error)
	RecordLoginResult(ctx context.Context, result *LoginResult) error
	AsSignalProvider() SignalProvider
}

type geoRecord struct {
	Location  string
	Timestamp time.Time
}

// InMemoryIdentityRiskAssessor implements IdentityRiskAssessor with in-memory storage.
type InMemoryIdentityRiskAssessor struct {
	mu           sync.RWMutex
	store        StateStore
	loginHistory map[string][]LoginResult          // userID -> recent results
	knownDevices map[string]map[string]time.Time   // userID -> deviceID -> lastSeen
	lastGeo      map[string]geoRecord              // userID -> last geo
	config       IdentityRiskConfig
}

// NewInMemoryIdentityRiskAssessor creates a new InMemoryIdentityRiskAssessor.
func NewInMemoryIdentityRiskAssessor(store StateStore, config IdentityRiskConfig) *InMemoryIdentityRiskAssessor {
	if config.FailedLoginThreshold <= 0 {
		config.FailedLoginThreshold = 5
	}
	if config.FailedLoginWindow <= 0 {
		config.FailedLoginWindow = 15 * time.Minute
	}
	if config.ImpossibleTravelSpeedKmH <= 0 {
		config.ImpossibleTravelSpeedKmH = 900 // ~speed of commercial aircraft
	}
	if config.NewDeviceWeight <= 0 {
		config.NewDeviceWeight = 0.3
	}
	if config.FailedStreakWeight <= 0 {
		config.FailedStreakWeight = 0.4
	}
	return &InMemoryIdentityRiskAssessor{
		store:        store,
		loginHistory: make(map[string][]LoginResult),
		knownDevices: make(map[string]map[string]time.Time),
		lastGeo:      make(map[string]geoRecord),
		config:       config,
	}
}

// AssessLogin evaluates the risk of a login attempt.
func (a *InMemoryIdentityRiskAssessor) AssessLogin(ctx context.Context, req *LoginRiskRequest) (*LoginRiskVerdict, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	verdict := &LoginRiskVerdict{
		Confidence: 1.0,
	}
	var totalScore float64

	// 1. Failed attempt streak
	failedStreak := a.countRecentFailures(req.UserID)
	if failedStreak > 0 {
		ratio := float64(failedStreak) / float64(a.config.FailedLoginThreshold)
		if ratio > 1.0 {
			ratio = 1.0
		}
		streakScore := ratio * a.config.FailedStreakWeight
		totalScore += streakScore
		if failedStreak >= a.config.FailedLoginThreshold {
			verdict.Factors = append(verdict.Factors, "failed_login_threshold_exceeded")
		} else {
			verdict.Factors = append(verdict.Factors, "elevated_failed_logins")
		}
	}

	// 2. New device check
	if req.DeviceID != "" {
		devices, exists := a.knownDevices[req.UserID]
		if !exists || devices == nil {
			totalScore += a.config.NewDeviceWeight
			verdict.Factors = append(verdict.Factors, "unknown_user")
			verdict.Confidence = 0.5
		} else if _, known := devices[req.DeviceID]; !known {
			totalScore += a.config.NewDeviceWeight
			verdict.Factors = append(verdict.Factors, "new_device")
		}
	}

	// 3. Impossible travel
	if req.GeoLocation != "" {
		if last, exists := a.lastGeo[req.UserID]; exists && last.Location != "" && last.Location != req.GeoLocation {
			elapsed := req.Timestamp.Sub(last.Timestamp)
			if elapsed > 0 {
				// Simplified: different geo strings within short time = suspicious
				// In production, this would use actual lat/lon distance calculation
				if elapsed < 1*time.Hour {
					totalScore += 0.3
					verdict.Factors = append(verdict.Factors, "impossible_travel")
				}
			}
		}
	}

	// 4. Account lock state (via store)
	if a.store != nil {
		lockState, err := a.store.GetAccountLock(req.UserID)
		if err == nil && lockState != nil && lockState.Locked && lockState.UnlockAt.After(time.Now()) {
			totalScore += 0.5
			verdict.Factors = append(verdict.Factors, "account_locked")
			verdict.AccountAction = "lockout"
		}
	}

	// 5. IP reputation (check ban)
	if a.store != nil {
		ban, err := a.store.GetBan(req.ClientIP)
		if err == nil && ban != nil {
			if ban.Permanent || ban.Until.After(time.Now()) {
				totalScore += 0.4
				verdict.Factors = append(verdict.Factors, "ip_banned")
			}
		}
	}

	// Clamp score to [0, 1]
	if totalScore > 1.0 {
		totalScore = 1.0
	}
	verdict.Score = totalScore

	// Determine account action based on score
	if verdict.AccountAction == "" {
		switch {
		case totalScore >= 0.9:
			verdict.AccountAction = "freeze"
		case totalScore >= 0.7:
			verdict.AccountAction = "lockout"
		case totalScore >= 0.5:
			verdict.AccountAction = "challenge"
		}
	}

	return verdict, nil
}

// countRecentFailures counts consecutive failed login attempts within the configured window.
func (a *InMemoryIdentityRiskAssessor) countRecentFailures(userID string) int {
	history, exists := a.loginHistory[userID]
	if !exists {
		return 0
	}
	cutoff := time.Now().Add(-a.config.FailedLoginWindow)
	count := 0
	// Walk backwards through history; stop at first success or expired entry
	for i := len(history) - 1; i >= 0; i-- {
		entry := history[i]
		if entry.Timestamp.Before(cutoff) {
			break
		}
		if entry.Success {
			break
		}
		count++
	}
	return count
}

// RecordLoginResult stores the result of a login attempt.
func (a *InMemoryIdentityRiskAssessor) RecordLoginResult(ctx context.Context, result *LoginResult) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Append to login history, cap at 1000
	history := a.loginHistory[result.UserID]
	history = append(history, *result)
	if len(history) > 1000 {
		history = history[len(history)-1000:]
	}
	a.loginHistory[result.UserID] = history

	// Update known devices
	if result.DeviceID != "" {
		if a.knownDevices[result.UserID] == nil {
			a.knownDevices[result.UserID] = make(map[string]time.Time)
		}
		if result.Success {
			a.knownDevices[result.UserID][result.DeviceID] = result.Timestamp
		}
	}

	// Update last geo
	if result.GeoLocation != "" {
		a.lastGeo[result.UserID] = geoRecord{
			Location:  result.GeoLocation,
			Timestamp: result.Timestamp,
		}
	}

	return nil
}

// AsSignalProvider returns a SignalProvider function for integration with the risk scorer.
func (a *InMemoryIdentityRiskAssessor) AsSignalProvider() SignalProvider {
	return func(ctx context.Context, req *RiskRequest, store StateStore) (RiskSignal, error) {
		ip := req.IP
		if ip == "" {
			ip = req.ClientIP
		}
		deviceID := req.DeviceFingerprint
		if deviceID == "" {
			deviceID = req.DeviceID
		}
		loginReq := &LoginRiskRequest{
			UserID:    req.UserID,
			DeviceID:  deviceID,
			ClientIP:  ip,
			UserAgent: req.UserAgent,
			Timestamp: time.Now(),
		}
		verdict, err := a.AssessLogin(ctx, loginReq)
		if err != nil {
			return RiskSignal{}, err
		}
		return RiskSignal{
			Name:   "identity_risk",
			Score:  verdict.Score,
			Weight: 1.0,
			Reason: "identity_risk_assessor",
		}, nil
	}
}

// Ensure InMemoryIdentityRiskAssessor implements IdentityRiskAssessor.
var _ IdentityRiskAssessor = (*InMemoryIdentityRiskAssessor)(nil)
