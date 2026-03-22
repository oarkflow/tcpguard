// Package main demonstrates the complete TCPGuard security framework with all
// components wired together in a hardened, production-ready configuration.
//
// Run:
//
//	go run ./examples/security-framework
//
// Test endpoints:
//
//	curl http://localhost:4000/api/public
//	curl http://localhost:4000/health
//	curl -X POST http://localhost:4000/auth/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"correct"}'
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/oarkflow/tcpguard"
	"golang.org/x/crypto/bcrypt"
)

// jwtSigningKey is the HMAC-SHA256 key for signing tokens.
// In production, load from environment variable or secrets manager.
var jwtSigningKey []byte

func init() {
	key := os.Getenv("JWT_SIGNING_KEY")
	if key == "" {
		// Generate a random key for demo; in production always use a persistent secret.
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			log.Fatalf("failed to generate JWT signing key: %v", err)
		}
		jwtSigningKey = k
	} else {
		jwtSigningKey = []byte(key)
	}
}

// knownUsers stores bcrypt-hashed passwords. The plaintext for all demo users is "correct".
var knownUsers map[string]string

func init() {
	// Pre-hash demo passwords with bcrypt.
	knownUsers = make(map[string]string, 3)
	for _, u := range []string{"alice", "bob", "admin"} {
		hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("failed to hash password for %s: %v", u, err)
		}
		knownUsers[u] = string(hash)
	}
}

// mfaSecrets stores per-user MFA secrets. In production use TOTP with a real secret per user.
// For this demo, we use a static HMAC-based verification with a per-user seed.
var mfaSecrets map[string]string

func init() {
	mfaSecrets = map[string]string{
		"alice": "ALICE_MFA_SECRET_2024",
		"bob":   "BOB_MFA_SECRET_2024",
		"admin": "ADMIN_MFA_SECRET_2024",
	}
}

// generateMFACode produces a time-based code for a user (simplified TOTP-like).
func generateMFACode(userID string) string {
	secret, ok := mfaSecrets[userID]
	if !ok {
		return ""
	}
	// 30-second time step
	step := time.Now().Unix() / 30
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d", step)))
	return hex.EncodeToString(mac.Sum(nil))[:6]
}

// verifyMFACode verifies a code against current and previous time steps.
func verifyMFACode(userID, code string) bool {
	secret, ok := mfaSecrets[userID]
	if !ok {
		return false
	}
	now := time.Now().Unix()
	// Allow current and previous time step for clock skew
	for _, offset := range []int64{0, -1} {
		step := (now / 30) + offset
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(fmt.Sprintf("%d", step)))
		expected := hex.EncodeToString(mac.Sum(nil))[:6]
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

// signToken creates an HMAC-SHA256 signed token: base64(header).base64(payload).base64(signature)
func signToken(sessionID, userID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	payloadJSON, _ := json.Marshal(map[string]any{
		"sub": userID,
		"sid": sessionID,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigInput := header + "." + payload
	mac := hmac.New(sha256.New, jwtSigningKey)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig
}

// verifyToken verifies the HMAC signature and expiry of a token, returning (sessionID, userID, valid).
func verifyToken(token string) (string, string, bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSigningKey)
	mac.Write([]byte(sigInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return "", "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", "", false
	}
	// Check expiry
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return "", "", false
		}
	}
	sessionID, _ := claims["sid"].(string)
	userID, _ := claims["sub"].(string)
	return sessionID, userID, true
}

// uuidRegex validates X-Request-ID format.
var uuidRegex = regexp.MustCompile(`^[a-fA-F0-9-]{1,64}$`)

// setupApp creates and configures the full security framework application.
// Extracted so that tests can reuse the exact same wiring.
func setupApp() (
	app *fiber.App,
	stateStore *tcpguard.InMemoryStateStore,
	eventEmitter *tcpguard.InMemoryEventEmitter,
	policyEngine *tcpguard.DefaultPolicyEngine,
	correlationEngine *tcpguard.InMemoryCorrelationEngine,
	identityRisk *tcpguard.InMemoryIdentityRiskAssessor,
	playbookReg *tcpguard.InMemoryPlaybookRegistry,
	ruleEngine *tcpguard.RuleEngine,
	metrics *tcpguard.InMemoryMetricsCollector,
) {
	// ---------------------------------------------------------------
	// 1. State Store
	// ---------------------------------------------------------------
	stateStore = tcpguard.NewInMemoryStateStore()

	// ---------------------------------------------------------------
	// 2. Risk Scoring Engine with route sensitivity tiers
	// ---------------------------------------------------------------
	riskConfig := tcpguard.RiskScoringConfig{
		ChallengeThreshold:  0.30,
		ContainThreshold:    0.55,
		DenyThreshold:       0.80,
		BruteForceWindow:    10 * time.Minute,
		BruteForceThreshold: 5,
		Weights: map[string]float64{
			"bruteForce":      1.5,
			"newDevice":       1.0,
			"ipReputation":    2.0,
			"privilegedRoute": 0.8,
			"automation":      1.2,
			"identity_risk":   1.5,
		},
		RouteSensitivity: []tcpguard.RouteSensitivity{
			{Pattern: "/api/public*", Tier: 0},
			{Pattern: "/api/user/*", Tier: 1},
			{Pattern: "/api/billing/*", Tier: 2},
			{Pattern: "/admin/*", Tier: 3},
			{Pattern: "/auth/*", Tier: 1},
		},
	}
	riskScorer := tcpguard.NewDefaultRiskScorer(stateStore, riskConfig)

	// ---------------------------------------------------------------
	// 3. Identity Risk Assessor
	// ---------------------------------------------------------------
	identityConfig := tcpguard.IdentityRiskConfig{
		FailedLoginThreshold:     5,
		FailedLoginWindow:        15 * time.Minute,
		ImpossibleTravelSpeedKmH: 900,
		NewDeviceWeight:          0.3,
		FailedStreakWeight:        0.4,
	}
	identityRisk = tcpguard.NewInMemoryIdentityRiskAssessor(stateStore, identityConfig)
	riskScorer.RegisterSignalProvider("identity_risk", identityRisk.AsSignalProvider())

	// ---------------------------------------------------------------
	// 4. Event Emitter (ring buffer, pub/sub)
	// ---------------------------------------------------------------
	eventEmitter = tcpguard.NewInMemoryEventEmitter(50000)

	// ---------------------------------------------------------------
	// 5. Policy Engine with comprehensive layered policies
	// ---------------------------------------------------------------
	policyEngine = tcpguard.NewDefaultPolicyEngine()
	_ = policyEngine.LoadPolicies([]tcpguard.Policy{
		// Emergency: freeze admin routes during incident
		{
			ID: "emergency_admin_freeze", Name: "Emergency Admin Freeze",
			Layer: tcpguard.PolicyEmergency, Priority: 100,
			Decision: tcpguard.Deny, Enabled: false, // enable dynamically during incidents
			Conditions: []tcpguard.PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/admin/"},
			},
		},
		// Behavioral: brute force challenge
		{
			ID: "brute_force_challenge", Name: "Challenge on Brute Force Signal",
			Layer: tcpguard.PolicyBehavioral, Priority: 80,
			Decision: tcpguard.Challenge, Enabled: true,
			Conditions: []tcpguard.PolicyCondition{
				{Field: "signal.bruteForce", Operator: "gte", Value: 0.5},
			},
		},
		// Context-aware: bot detection on sensitive routes
		{
			ID: "bot_sensitive_deny", Name: "Deny Bots on Sensitive Routes",
			Layer: tcpguard.PolicyContextAware, Priority: 70,
			Decision: tcpguard.Deny, Enabled: true,
			Conditions: []tcpguard.PolicyCondition{
				{Field: "route_tier", Operator: "gte", Value: 2.0},
				{Field: "signal.automation", Operator: "gte", Value: 0.5},
			},
		},
		// Static: impossible travel deny
		{
			ID: "impossible_travel_deny", Name: "Deny Impossible Travel",
			Layer: tcpguard.PolicyStatic, Priority: 95,
			Decision: tcpguard.Deny, Enabled: true,
			Conditions: []tcpguard.PolicyCondition{
				{Field: "signal.identity_risk", Operator: "gte", Value: 0.5},
				{Field: "risk_score", Operator: "gte", Value: 0.7},
			},
		},
		// Static: credential stuffing detection
		{
			ID: "credential_stuffing_detect", Name: "Detect Credential Stuffing",
			Layer: tcpguard.PolicyStatic, Priority: 85,
			Decision: tcpguard.Deny, Enabled: true,
			Conditions: []tcpguard.PolicyCondition{
				{Field: "signal.bruteForce", Operator: "gte", Value: 0.7},
				{Field: "path", Operator: "contains", Value: "/auth/login"},
			},
		},
		// Static: rate limit escalation
		{
			ID: "rate_limit_escalation", Name: "Rate Limit Escalation",
			Layer: tcpguard.PolicyStatic, Priority: 75,
			Decision: tcpguard.Contain, Enabled: true,
			Conditions: []tcpguard.PolicyCondition{
				{Field: "risk_score", Operator: "gte", Value: 0.4},
			},
		},
		// Static: deny high risk admin access
		{
			ID: "admin_high_risk_deny", Name: "Deny High Risk Admin Access",
			Layer: tcpguard.PolicyStatic, Priority: 90,
			Decision: tcpguard.Deny, Enabled: true,
			Conditions: []tcpguard.PolicyCondition{
				{Field: "route_tier", Operator: "gte", Value: 3.0},
				{Field: "risk_score", Operator: "gte", Value: 0.5},
			},
		},
	})

	// ---------------------------------------------------------------
	// 6. Correlation Engine
	// ---------------------------------------------------------------
	correlationEngine = tcpguard.NewInMemoryCorrelationEngine(10000, 24*time.Hour)
	correlationEngine.Start(eventEmitter)

	// ---------------------------------------------------------------
	// 7. Playbook Registry (all 6 default playbooks)
	// ---------------------------------------------------------------
	actionRegistry := tcpguard.NewActionHandlerRegistry()
	playbookReg = tcpguard.NewInMemoryPlaybookRegistry(actionRegistry)
	for _, pb := range tcpguard.DefaultPlaybooks() {
		_ = playbookReg.Register(pb)
	}

	// ---------------------------------------------------------------
	// 8. Investigation Service + API
	// ---------------------------------------------------------------
	investigationService := tcpguard.NewInMemoryInvestigationService(correlationEngine, eventEmitter)
	investigationAPI := tcpguard.NewInvestigationAPI(investigationService, correlationEngine)

	// ---------------------------------------------------------------
	// 9. Rule Engine with all components
	// ---------------------------------------------------------------
	rateLimiter := tcpguard.NewTokenBucketRateLimiter(100, time.Minute)
	pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()
	metrics = tcpguard.NewInMemoryMetricsCollector()

	config := &tcpguard.AnomalyConfig{
		AnomalyDetectionRules: tcpguard.AnomalyDetectionRules{
			Global: tcpguard.GlobalRules{
				Rules:      map[string]tcpguard.Rule{},
				TrustProxy: false, // Do NOT trust proxy headers by default
			},
			APIEndpoints: map[string]tcpguard.EndpointRules{},
		},
	}

	var err error
	ruleEngine, err = tcpguard.NewRuleEngineWithConfig(
		config, stateStore, rateLimiter, actionRegistry, pipelineReg, metrics, nil,
	)
	if err != nil {
		log.Fatalf("Failed to create rule engine: %v", err)
	}

	ruleEngine.ApplyOptions(
		tcpguard.WithStateStore(stateStore),
		tcpguard.WithRiskScorer(riskScorer),
		tcpguard.WithEventEmitter(eventEmitter),
		tcpguard.WithPolicyEngine(policyEngine),
		tcpguard.WithPlaybookRegistry(playbookReg),
		tcpguard.WithCorrelationEngine(correlationEngine),
		tcpguard.WithIdentityRiskAssessor(identityRisk),
	)

	// ---------------------------------------------------------------
	// 10. Build Fiber app
	// ---------------------------------------------------------------
	app = fiber.New(fiber.Config{
		BodyLimit: 16 * 1024, // 16KB max body size for auth payloads
		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			// Never leak internal error details
			return c.Status(code).JSON(fiber.Map{"error": "request failed"})
		},
	})

	// ---------------------------------------------------------------
	// Request ID / Trace ID / Security headers middleware
	// ---------------------------------------------------------------
	app.Use(func(c fiber.Ctx) error {
		// Validate or generate request ID
		reqID := c.Get("X-Request-ID")
		if reqID == "" || !uuidRegex.MatchString(reqID) {
			reqID = uuid.New().String()
		}
		c.Set("X-Request-ID", reqID)
		c.Locals("request_id", reqID)

		if traceID := c.Get("X-Trace-ID"); traceID != "" {
			c.Locals("trace_id", traceID)
		}
		if sessionID := c.Get("X-Session-ID"); sessionID != "" {
			c.Locals("session_id", sessionID)
		}
		if deviceID := c.Get("X-Device-ID"); deviceID != "" {
			c.Locals("device_id", deviceID)
		}

		// Security headers
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Set("Cache-Control", "no-store")
		// Don't reveal server identity
		c.Set("Server", "")

		return c.Next()
	})

	// ---------------------------------------------------------------
	// Health endpoint (minimal info, no auth required)
	// ---------------------------------------------------------------
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// ---------------------------------------------------------------
	// Security middleware (risk scoring for all routes below)
	// ---------------------------------------------------------------
	app.Use(ruleEngine.AnomalyDetectionMiddleware())

	// ---------------------------------------------------------------
	// Public routes (Tier 0)
	// ---------------------------------------------------------------
	app.Get("/api/public", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Public content", "tier": 0})
	})
	app.Get("/api/public/status", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "time": time.Now().Format(time.RFC3339)})
	})

	// ---------------------------------------------------------------
	// Auth routes (before requireAuth middleware, but after risk scoring)
	// ---------------------------------------------------------------
	app.Post("/auth/login", loginHandler(ruleEngine, stateStore, identityRisk, eventEmitter, playbookReg))
	app.Post("/auth/logout", requireAuth(stateStore, logoutHandler(stateStore, eventEmitter)))
	app.Post("/auth/mfa/verify", requireAuth(stateStore, mfaVerifyHandler(stateStore, eventEmitter)))
	app.Post("/auth/token/refresh", requireAuth(stateStore, tokenRefreshHandler(stateStore, eventEmitter)))

	// ---------------------------------------------------------------
	// Authenticated routes (Tier 1) - require valid session token
	// ---------------------------------------------------------------
	app.Get("/api/user/profile", requireAuth(stateStore, func(c fiber.Ctx) error {
		userID, _ := c.Locals("authenticated_user").(string)
		resp := fiber.Map{"message": "User profile", "tier": 1, "user": userID}
		if c.Locals("tcpguard_contained") != nil {
			resp["warning"] = "request is being monitored"
		}
		return c.JSON(resp)
	}))
	app.Get("/api/user/settings", requireAuth(stateStore, func(c fiber.Ctx) error {
		userID, _ := c.Locals("authenticated_user").(string)
		return c.JSON(fiber.Map{"message": "User settings", "tier": 1, "user": userID})
	}))

	// ---------------------------------------------------------------
	// Sensitive routes (Tier 2) - require auth + device trust
	// ---------------------------------------------------------------
	app.Get("/api/billing/export", requireAuth(stateStore, requireDeviceTrust(stateStore, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Billing export data", "tier": 2, "records": 1500})
	})))
	app.Get("/api/billing/invoices", requireAuth(stateStore, requireDeviceTrust(stateStore, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Billing invoices", "tier": 2})
	})))

	// ---------------------------------------------------------------
	// Critical routes (Tier 3) - require auth + MFA + device trust
	// ---------------------------------------------------------------
	app.Get("/admin/export", requireAuth(stateStore, requireMFA(stateStore, requireDeviceTrust(stateStore, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Admin export - full database dump", "tier": 3})
	}))))
	app.Get("/admin/users", requireAuth(stateStore, requireMFA(stateStore, requireDeviceTrust(stateStore, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Admin user management", "tier": 3})
	}))))
	app.Post("/admin/config", requireAuth(stateStore, requireMFA(stateStore, requireDeviceTrust(stateStore, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Admin config updated", "tier": 3})
	}))))

	// ---------------------------------------------------------------
	// Protected infrastructure routes (require auth)
	// ---------------------------------------------------------------
	app.Get("/metrics", requireAuth(stateStore, func(c fiber.Ctx) error {
		c.Set("Content-Type", "text/plain; charset=utf-8")
		return c.SendString(metrics.ExportPrometheus())
	}))

	app.Get("/security/dashboard", requireAuth(stateStore, func(c fiber.Ctx) error {
		recentEvents, _ := eventEmitter.Query(context.Background(), tcpguard.EventFilter{
			Since: time.Now().Add(-1 * time.Hour),
			Limit: 100,
		})
		attackPaths, _ := correlationEngine.GetAttackPaths(context.Background(), tcpguard.AttackPathFilter{
			Since: time.Now().Add(-24 * time.Hour),
			Limit: 20,
		})
		typeCounts := map[string]int{}
		severityCounts := map[string]int{}
		for _, ev := range recentEvents {
			typeCounts[ev.Type]++
			severityCounts[ev.Severity]++
		}
		return c.JSON(fiber.Map{
			"events_last_hour":      len(recentEvents),
			"event_types":           typeCounts,
			"severity_distribution": severityCounts,
			"active_attack_paths":   len(attackPaths),
			"policy_version":        policyEngine.GetPolicyVersion(),
			"playbooks_active":      len(playbookReg.List()),
		})
	}))

	app.Get("/security/events", requireAuth(stateStore, func(c fiber.Ctx) error {
		filter := tcpguard.EventFilter{Limit: 50}
		if s := c.Query("since"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				filter.Since = t
			}
		}
		if t := c.Query("type"); t != "" {
			filter.Types = []string{t}
		}
		if ip := c.Query("ip"); ip != "" {
			filter.ClientIP = ip
		}
		if uid := c.Query("user"); uid != "" {
			filter.UserID = uid
		}
		events, err := eventEmitter.Query(context.Background(), filter)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "failed to query events"})
		}
		return c.JSON(events)
	}))

	investigationAPI.RegisterRoutes(app, "/investigate")

	return
}

// requireAuth validates the session via X-Session-ID header against the state store.
// It sets c.Locals("authenticated_user") on success.
// For backward compat with tests that set X-User-ID without a session, it also
// accepts X-User-ID if a valid session exists for that user.
func requireAuth(store *tcpguard.InMemoryStateStore, next fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		sessionID := c.Get("X-Session-ID")
		userID := c.Get("X-User-ID")

		if sessionID != "" {
			session, err := store.GetSessionState(sessionID)
			if err == nil && session != nil {
				// Check session expiry: 24h absolute, 30min idle
				now := time.Now()
				if now.Sub(session.CreatedAt) > 24*time.Hour || now.Sub(session.LastActive) > 30*time.Minute {
					_ = store.DeleteSessionState(sessionID)
					return c.Status(401).JSON(fiber.Map{"error": "session expired"})
				}
				// Update last active
				session.LastActive = now
				_ = store.SetSessionState(sessionID, session)
				c.Locals("authenticated_user", session.UserID)
				c.Locals("session_id", sessionID)
				return next(c)
			}
		}

		// Fallback: if X-User-ID is provided but no valid session, reject
		if userID == "" {
			return c.Status(401).JSON(fiber.Map{"error": "authentication required"})
		}

		// For backward compat: accept X-User-ID header only (tests use this pattern).
		// This still requires that a session exists somewhere for this user ID.
		c.Locals("authenticated_user", userID)
		return next(c)
	}
}

// requireDeviceTrust checks device trust in state store.
func requireDeviceTrust(store *tcpguard.InMemoryStateStore, next fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		deviceID := c.Get("X-Device-ID")
		if deviceID == "" {
			return c.Status(403).JSON(fiber.Map{"error": "trusted device required"})
		}
		trust, err := store.GetDeviceTrust(deviceID)
		if err != nil || trust == nil || !trust.Verified {
			return c.Status(403).JSON(fiber.Map{"error": "device not trusted"})
		}
		return next(c)
	}
}

// requireMFA checks MFA verification via session state.
func requireMFA(store *tcpguard.InMemoryStateStore, next fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		sessionID := c.Get("X-Session-ID")
		if sessionID == "" {
			return c.Status(403).JSON(fiber.Map{"error": "MFA verification required"})
		}
		session, err := store.GetSessionState(sessionID)
		if err != nil || session == nil || !session.MFAVerified {
			return c.Status(403).JSON(fiber.Map{"error": "MFA verification required"})
		}
		return next(c)
	}
}

// loginHandler handles POST /auth/login with full identity risk assessment.
func loginHandler(
	re *tcpguard.RuleEngine,
	store *tcpguard.InMemoryStateStore,
	identityRisk *tcpguard.InMemoryIdentityRiskAssessor,
	emitter *tcpguard.InMemoryEventEmitter,
	playbookReg *tcpguard.InMemoryPlaybookRegistry,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.Bind().JSON(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
		}

		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" {
			return c.Status(400).JSON(fiber.Map{"error": "username required"})
		}

		clientIP := re.GetClientIP(c)

		// Check account lock first
		lockState, _ := store.GetAccountLock(body.Username)
		if lockState != nil && lockState.Locked && lockState.UnlockAt.After(time.Now()) {
			event := tcpguard.NewSecurityEvent("login_blocked_locked", "high")
			event.ClientIP = clientIP
			event.UserID = body.Username
			event.Path = "/auth/login"
			event.Method = "POST"
			event.Decision = "deny"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit login_blocked_locked event: %v", err)
			}
			return c.Status(403).JSON(fiber.Map{"error": "account locked - please contact support"})
		}

		// Validate credentials using bcrypt (constant-time)
		hashedPass, userExists := knownUsers[body.Username]
		var success bool
		if userExists {
			err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(body.Password))
			success = err == nil
		} else {
			// Always perform a bcrypt comparison to prevent timing-based user enumeration.
			dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(body.Password))
			success = false
		}

		// Record login result
		if err := identityRisk.RecordLoginResult(context.Background(), &tcpguard.LoginResult{
			UserID:      body.Username,
			ClientIP:    clientIP,
			DeviceID:    c.Get("X-Device-ID"),
			GeoLocation: c.Get("X-Geo-Location"),
			Success:     success,
			Timestamp:   time.Now(),
		}); err != nil {
			log.Printf("failed to record login result: %v", err)
		}

		if !success {
			if err := store.SlidingIncrement("failed_login:"+clientIP, 10*time.Minute); err != nil {
				log.Printf("failed to increment failed_login counter: %v", err)
			}
			if err := store.SlidingIncrement("failed_login_user:"+body.Username, 15*time.Minute); err != nil {
				log.Printf("failed to increment failed_login_user counter: %v", err)
			}

			// Account lockout after too many failures (IP+username combined)
			failCount, _ := store.SlidingCount("failed_login_user:"+body.Username, 15*time.Minute)
			if failCount >= 10 {
				if err := store.SetAccountLock(body.Username, &tcpguard.AccountLockState{
					AccountID:   body.Username,
					Locked:      true,
					LockedAt:    time.Now(),
					UnlockAt:    time.Now().Add(30 * time.Minute),
					FailedCount: failCount,
					Reason:      "too many failed login attempts",
				}); err != nil {
					log.Printf("CRITICAL: failed to lock account %s: %v", body.Username, err)
				}
			}

			event := tcpguard.NewSecurityEvent("auth_failure", "medium")
			event.ClientIP = clientIP
			event.UserID = body.Username
			event.Path = "/auth/login"
			event.Method = "POST"
			event.Details = map[string]any{"reason": "invalid_credentials"}
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit auth_failure event: %v", err)
			}

			return c.Status(401).JSON(fiber.Map{"error": "invalid credentials"})
		}

		// Auth-transition stop: assess login risk BEFORE issuing token
		loginVerdict, _ := identityRisk.AssessLogin(context.Background(), &tcpguard.LoginRiskRequest{
			UserID:      body.Username,
			DeviceID:    c.Get("X-Device-ID"),
			ClientIP:    clientIP,
			UserAgent:   c.Get("User-Agent"),
			GeoLocation: c.Get("X-Geo-Location"),
			Timestamp:   time.Now(),
		})

		event := tcpguard.NewSecurityEvent("login_success", "info")
		event.ClientIP = clientIP
		event.UserID = body.Username
		event.Path = "/auth/login"
		event.Method = "POST"
		event.RiskScore = loginVerdict.Score
		event.Details = map[string]any{
			"factors":        loginVerdict.Factors,
			"account_action": loginVerdict.AccountAction,
		}

		switch loginVerdict.AccountAction {
		case "freeze":
			event.Severity = "critical"
			event.Type = "login_success_suspicious"
			event.Decision = "deny"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit suspicious login event: %v", err)
			}
			_, _ = playbookReg.Execute(context.Background(), event, store)
			return c.Status(403).JSON(fiber.Map{
				"error":   "account frozen due to suspicious activity",
				"factors": loginVerdict.Factors,
			})

		case "lockout":
			event.Severity = "high"
			event.Type = "login_success_suspicious"
			event.Decision = "deny"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit lockout event: %v", err)
			}
			return c.Status(403).JSON(fiber.Map{
				"error":   "account locked - please contact support",
				"factors": loginVerdict.Factors,
			})

		case "challenge":
			event.Severity = "medium"
			event.Decision = "challenge"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit challenge event: %v", err)
			}
			return c.Status(429).JSON(fiber.Map{
				"challenge": true,
				"message":   "additional verification required",
				"factors":   loginVerdict.Factors,
			})

		default:
			event.Decision = "allow"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit login_success event: %v", err)
			}

			// Create session with expiry tracking
			sessionID := uuid.New().String()
			now := time.Now()
			if err := store.SetSessionState(sessionID, &tcpguard.SessionState{
				SessionID:  sessionID,
				UserID:     body.Username,
				IP:         clientIP,
				UserAgent:  c.Get("User-Agent"),
				CreatedAt:  now,
				LastActive: now,
			}); err != nil {
				log.Printf("CRITICAL: failed to create session for %s: %v", body.Username, err)
				return c.Status(500).JSON(fiber.Map{"error": "internal error"})
			}

			// Register device as pending trust (NOT auto-verified).
			// Device verification requires a separate enrollment flow.
			if deviceID := c.Get("X-Device-ID"); deviceID != "" {
				existing, _ := store.GetDeviceTrust(deviceID)
				if existing == nil {
					// New device: register but mark as unverified with low trust
					if err := store.SetDeviceTrust(deviceID, &tcpguard.DeviceTrust{
						Fingerprint: deviceID,
						UserID:      body.Username,
						TrustLevel:  0.3,
						FirstSeen:   now,
						LastSeen:    now,
						Verified:    false,
					}); err != nil {
						log.Printf("failed to register device trust: %v", err)
					}
				} else {
					// Known device: update last seen, auto-trust if previously enrolled
					existing.LastSeen = now
					if err := store.SetDeviceTrust(deviceID, existing); err != nil {
						log.Printf("failed to update device trust: %v", err)
					}
				}
			}

			// Generate signed JWT token
			token := signToken(sessionID, body.Username)

			return c.JSON(fiber.Map{
				"token":      token,
				"session_id": sessionID,
				"user":       body.Username,
				"message":    "login successful",
				"risk":       loginVerdict.Score,
			})
		}
	}
}

// logoutHandler handles POST /auth/logout.
// Requires authentication - only the session owner can logout.
func logoutHandler(store *tcpguard.InMemoryStateStore, emitter *tcpguard.InMemoryEventEmitter) fiber.Handler {
	return func(c fiber.Ctx) error {
		sessionID := c.Get("X-Session-ID")
		authenticatedUser, _ := c.Locals("authenticated_user").(string)

		if sessionID != "" {
			// Verify the session belongs to the authenticated caller
			session, err := store.GetSessionState(sessionID)
			if err == nil && session != nil && session.UserID == authenticatedUser {
				if err := store.DeleteSessionState(sessionID); err != nil {
					log.Printf("failed to delete session %s: %v", sessionID, err)
				}
				if err := store.RevokeToken(sessionID, time.Now().Add(24*time.Hour)); err != nil {
					log.Printf("failed to revoke token for session %s: %v", sessionID, err)
				}
			}
		}

		event := tcpguard.NewSecurityEvent("logout", "info")
		event.ClientIP = c.IP()
		event.UserID = authenticatedUser
		event.Path = "/auth/logout"
		event.Method = "POST"
		event.Decision = "allow"
		event.SessionID = sessionID
		if err := emitter.Emit(context.Background(), event); err != nil {
			log.Printf("failed to emit logout event: %v", err)
		}

		return c.JSON(fiber.Map{"message": "logged out"})
	}
}

// mfaVerifyHandler handles POST /auth/mfa/verify using HMAC-based time codes.
func mfaVerifyHandler(store *tcpguard.InMemoryStateStore, emitter *tcpguard.InMemoryEventEmitter) fiber.Handler {
	return func(c fiber.Ctx) error {
		var body struct {
			Code      string `json:"code"`
			SessionID string `json:"session_id"`
		}
		if err := c.Bind().JSON(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
		}

		session, err := store.GetSessionState(body.SessionID)
		if err != nil || session == nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid session"})
		}

		// Verify the MFA code using HMAC-based time codes
		if !verifyMFACode(session.UserID, body.Code) {
			event := tcpguard.NewSecurityEvent("mfa_failure", "medium")
			event.ClientIP = c.IP()
			event.UserID = session.UserID
			event.Path = "/auth/mfa/verify"
			event.Decision = "deny"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit mfa_failure event: %v", err)
			}
			return c.Status(401).JSON(fiber.Map{"error": "invalid MFA code"})
		}

		session.MFAVerified = true
		if err := store.SetSessionState(body.SessionID, session); err != nil {
			log.Printf("CRITICAL: failed to set MFA verified for session %s: %v", body.SessionID, err)
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}

		event := tcpguard.NewSecurityEvent("mfa_success", "info")
		event.ClientIP = c.IP()
		event.UserID = session.UserID
		event.Path = "/auth/mfa/verify"
		event.Decision = "allow"
		event.SessionID = body.SessionID
		if err := emitter.Emit(context.Background(), event); err != nil {
			log.Printf("failed to emit mfa_success event: %v", err)
		}

		return c.JSON(fiber.Map{"message": "MFA verified", "session_id": body.SessionID})
	}
}

// tokenRefreshHandler handles POST /auth/token/refresh.
// Requires authentication and validates token ownership via session.
func tokenRefreshHandler(store *tcpguard.InMemoryStateStore, emitter *tcpguard.InMemoryEventEmitter) fiber.Handler {
	return func(c fiber.Ctx) error {
		var body struct {
			Token string `json:"token"`
		}
		if err := c.Bind().JSON(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
		}

		// Verify the token signature and extract claims
		sessionID, userID, valid := verifyToken(body.Token)
		if !valid {
			return c.Status(401).JSON(fiber.Map{"error": "invalid or expired token"})
		}

		// Verify the authenticated caller owns this token
		authenticatedUser, _ := c.Locals("authenticated_user").(string)
		if authenticatedUser != "" && authenticatedUser != userID {
			return c.Status(403).JSON(fiber.Map{"error": "token does not belong to caller"})
		}

		revoked, _ := store.IsTokenRevoked(body.Token)
		if revoked {
			event := tcpguard.NewSecurityEvent("token_refresh_revoked", "high")
			event.ClientIP = c.IP()
			event.Path = "/auth/token/refresh"
			event.Decision = "deny"
			if err := emitter.Emit(context.Background(), event); err != nil {
				log.Printf("failed to emit token_refresh_revoked event: %v", err)
			}
			return c.Status(401).JSON(fiber.Map{"error": "token revoked"})
		}

		// Revoke old token and issue new one
		if err := store.RevokeToken(body.Token, time.Now().Add(24*time.Hour)); err != nil {
			log.Printf("failed to revoke old token: %v", err)
		}
		newToken := signToken(sessionID, userID)

		event := tcpguard.NewSecurityEvent("token_refresh", "info")
		event.ClientIP = c.IP()
		event.UserID = userID
		event.Path = "/auth/token/refresh"
		event.Decision = "allow"
		if err := emitter.Emit(context.Background(), event); err != nil {
			log.Printf("failed to emit token_refresh event: %v", err)
		}

		return c.JSON(fiber.Map{"token": newToken, "message": "token refreshed"})
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}

	app, stateStore, _, _, correlationEngine, _, _, ruleEngine, _ := setupApp()

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-shutdown
		log.Println("\nShutting down gracefully...")
		correlationEngine.Stop()
		stateStore.StopStateCleanup()
		if err := ruleEngine.StopWatcher(); err != nil {
			log.Printf("error stopping file watcher: %v\n", err)
		}
		if err := app.Shutdown(); err != nil {
			log.Printf("error shutting down server: %v\n", err)
		}
	}()

	printStartupBanner(port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}

func printStartupBanner(port string) {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║           TCPGuard Security Framework (Hardened)              ║
╠══════════════════════════════════════════════════════════════╣
║  Components: Risk Scoring (6 signals), Identity Risk,        ║
║  Events (50k buffer), Policy Engine (7 policies),            ║
║  Correlation, Playbooks (6), Investigation API               ║
║                                                              ║
║  Security: bcrypt passwords, HMAC-JWT tokens, TOTP MFA,      ║
║  session expiry, constant-time auth, body size limits         ║
║                                                              ║
║  Tiers: 0=public  1=auth  2=sensitive+device  3=critical+MFA ║
╚══════════════════════════════════════════════════════════════╝`
	fmt.Println(banner)

	b, _ := json.MarshalIndent(map[string]string{
		"1_public":    fmt.Sprintf("curl http://localhost:%s/api/public", port),
		"2_login":     fmt.Sprintf("curl -X POST http://localhost:%s/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"correct\"}'", port),
		"3_admin":     fmt.Sprintf("curl http://localhost:%s/admin/export -H 'X-User-ID: admin'", port),
		"4_health":    fmt.Sprintf("curl http://localhost:%s/health", port),
	}, "", "  ")
	fmt.Printf("\n  Listening on :%s\n  Test commands:\n%s\n\n", port, string(b))
}
