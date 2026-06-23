package tcpguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ResponseEnvironment controls how much diagnostic detail is safe to expose to
// clients. Production intentionally hides sensitive values while preserving a
// clear, actionable explanation and request trace for support/SOC lookup.
type ResponseEnvironment string

const (
	EnvironmentDevelopment ResponseEnvironment = "development"
	EnvironmentTest        ResponseEnvironment = "test"
	EnvironmentStaging     ResponseEnvironment = "staging"
	EnvironmentProduction  ResponseEnvironment = "production"
)

// ResponseDetailLevel controls public decision detail disclosure.
type ResponseDetailLevel string

const (
	ResponseDetailsNone ResponseDetailLevel = "none"
	ResponseDetailsSafe ResponseDetailLevel = "safe"
	ResponseDetailsFull ResponseDetailLevel = "full"
)

// ResponseMessagePolicy configures user-facing deny/challenge/throttle messages
// and public diagnostics. It is deliberately separate from internal audit,
// traces, evidence, and findings so production responses remain safe by default.
type ResponseMessagePolicy struct {
	Environment ResponseEnvironment
	DetailLevel ResponseDetailLevel

	// IncludeRiskScore exposes numeric risk to clients. Disable this in very
	// sensitive public APIs if risk values could help attackers tune requests.
	IncludeRiskScore bool
	// IncludeRuleIDs exposes matched rule IDs. In production this is false by
	// default; safe human categories are still returned.
	IncludeRuleIDs bool
	// IncludeFindingMessages exposes sanitized finding messages.
	IncludeFindingMessages bool
	// IncludeValues allows field/value diagnostics. Production defaults to false.
	IncludeValues bool
	// IncludeActions exposes public action summaries such as challenge/throttle.
	IncludeActions bool
	// IncludeEvidence exposes public evidence categories. Full evidence values are
	// only emitted when IncludeValues and DetailLevel=full are both enabled.
	IncludeEvidence bool
	// IncludeTrace includes request trace/request ID in body.
	IncludeTrace bool
	// IncludeHeaders adds X-TCPGuard-* metadata on rendered TCPGuard responses.
	IncludeHeaders bool

	// SupportMessage is appended to production-safe denied/challenged responses.
	SupportMessage string
	// SupportURL optionally points users/operators to remediation documentation.
	SupportURL string
	// CodePrefix is used to generate stable error codes.
	CodePrefix string
	// RedactFields are case-insensitive field-name fragments that must never be
	// exposed with raw values.
	RedactFields []string
	// MaxDetails bounds public detail array length.
	MaxDetails int
}

// DefaultResponseMessagePolicy returns a safe policy for the environment. Empty
// environment is treated as production unless TCPGUARD_ENV/APP_ENV/GO_ENV says
// otherwise.
func DefaultResponseMessagePolicy(env ResponseEnvironment) ResponseMessagePolicy {
	if env == "" {
		env = DetectResponseEnvironment()
	}
	p := ResponseMessagePolicy{
		Environment:            env,
		DetailLevel:            ResponseDetailsSafe,
		IncludeRiskScore:       true,
		IncludeFindingMessages: true,
		IncludeActions:         true,
		IncludeEvidence:        false,
		IncludeTrace:           true,
		IncludeHeaders:         true,
		SupportMessage:         "Contact support with the request_id if you believe this is a mistake.",
		CodePrefix:             "TCPGUARD",
		MaxDetails:             16,
		RedactFields:           DefaultSensitiveFieldNames(),
	}
	switch env {
	case EnvironmentDevelopment, EnvironmentTest:
		p.DetailLevel = ResponseDetailsFull
		p.IncludeRuleIDs = true
		p.IncludeValues = true
		p.IncludeEvidence = true
	case EnvironmentStaging:
		p.DetailLevel = ResponseDetailsSafe
		p.IncludeRuleIDs = true
		p.IncludeValues = false
		p.IncludeEvidence = true
	case EnvironmentProduction:
		p.DetailLevel = ResponseDetailsSafe
		p.IncludeRuleIDs = false
		p.IncludeValues = false
		p.IncludeEvidence = false
	}
	return p
}

// DetectResponseEnvironment inspects common env vars and defaults to production
// for safe failure.
func DetectResponseEnvironment() ResponseEnvironment {
	for _, key := range []string{"TCPGUARD_ENV", "APP_ENV", "GO_ENV", "ENVIRONMENT"} {
		if env := ParseResponseEnvironment(os.Getenv(key)); env != "" {
			return env
		}
	}
	return EnvironmentProduction
}

func ParseResponseEnvironment(value string) ResponseEnvironment {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "dev", "development", "local":
		return EnvironmentDevelopment
	case "test", "testing":
		return EnvironmentTest
	case "stage", "staging", "preprod", "pre-production":
		return EnvironmentStaging
	case "prod", "production":
		return EnvironmentProduction
	default:
		return ""
	}
}

func DefaultSensitiveFieldNames() []string {
	return []string{
		"authorization", "cookie", "set-cookie", "token", "secret", "password", "passwd", "pwd",
		"api_key", "apikey", "x-api-key", "key", "signature", "nonce", "hmac", "otp", "mfa",
		"card", "pan", "cvv", "cvc", "ssn", "dob", "email", "phone", "address", "session",
		"jwt", "bearer", "private", "credential", "body", "payload",
	}
}

// PublicDecisionBody builds a safe JSON-compatible response for a TCPGuard
// decision. It is suitable for HTTP clients and intentionally different from
// internal audit records.
func PublicDecisionBody(sec *Context, decision Decision, policy ResponseMessagePolicy) map[string]any {
	policy = normalizeResponsePolicy(policy)
	status := httpStatus(decision.Effect)
	code := publicDecisionCode(policy, decision)
	message := PublicDecisionMessage(sec, decision, policy)
	body := map[string]any{
		"code":        code,
		"message":     message,
		"description": publicDecisionDescription(sec, decision, policy),
		"effect":      decision.Effect,
		"allowed":     decision.Allowed,
		"status":      status,
		"severity":    decision.Severity,
	}
	if policy.IncludeTrace && sec != nil && sec.Request.ID != "" {
		body["request_id"] = sec.Request.ID
	}
	if policy.IncludeRiskScore {
		body["risk_score"] = decision.Risk.Score
		if decision.Risk.Confidence > 0 {
			body["confidence"] = decision.Risk.Confidence
		}
	}
	if policy.SupportURL != "" {
		body["support_url"] = policy.SupportURL
	}
	details := publicDecisionDetails(sec, decision, policy)
	if len(details) > 0 && policy.DetailLevel != ResponseDetailsNone {
		body["details"] = details
	}
	return body
}

// PublicDecisionMessage returns a concise, safe message for headers/logs/UI.
func PublicDecisionMessage(sec *Context, decision Decision, policy ResponseMessagePolicy) string {
	policy = normalizeResponsePolicy(policy)
	base := publicEffectMessage(decision)
	if policy.DetailLevel == ResponseDetailsFull && strings.TrimSpace(decision.Explanation) != "" {
		return sanitizePublicText(decision.Explanation, policy)
	}
	reason := topPublicReason(sec, decision, policy)
	if reason != "" {
		return base + " " + reason
	}
	return base
}

func PublicDecisionResponseRenderer(policy ResponseMessagePolicy) DecisionResponseRenderer {
	return func(sec *Context, decision Decision) DecisionResponse {
		policy = normalizeResponsePolicy(policy)
		body := PublicDecisionBody(sec, decision, policy)
		headers := map[string]string{"Content-Type": "application/json"}
		if policy.IncludeHeaders {
			headers["X-TCPGuard-Decision"] = string(decision.Effect)
			headers["X-TCPGuard-Severity"] = string(decision.Severity)
			if policy.IncludeRiskScore {
				headers["X-TCPGuard-Risk"] = fmt.Sprintf("%.0f", decision.Risk.Score)
			}
			if policy.IncludeTrace && sec != nil && sec.Request.ID != "" {
				headers["X-TCPGuard-Trace"] = sec.Request.ID
			}
			headers["X-TCPGuard-Message"] = headerSafeMessage(PublicDecisionMessage(sec, decision, policy))
		}
		return DecisionResponse{Status: httpStatus(decision.Effect), Headers: headers, Body: body}
	}
}

func normalizeResponsePolicy(policy ResponseMessagePolicy) ResponseMessagePolicy {
	if policy.Environment == "" {
		policy.Environment = DetectResponseEnvironment()
	}
	if policy.DetailLevel == "" {
		policy = mergeResponsePolicy(DefaultResponseMessagePolicy(policy.Environment), policy)
	}
	if len(policy.RedactFields) == 0 {
		policy.RedactFields = DefaultSensitiveFieldNames()
	}
	if policy.CodePrefix == "" {
		policy.CodePrefix = "TCPGUARD"
	}
	if policy.MaxDetails <= 0 {
		policy.MaxDetails = 16
	}
	if policy.Environment == EnvironmentProduction {
		if policy.DetailLevel == ResponseDetailsFull {
			policy.DetailLevel = ResponseDetailsSafe
		}
		policy.IncludeValues = false
	}
	return policy
}

func mergeResponsePolicy(base, override ResponseMessagePolicy) ResponseMessagePolicy {
	if override.Environment != "" {
		base.Environment = override.Environment
	}
	if override.DetailLevel != "" {
		base.DetailLevel = override.DetailLevel
	}
	if override.IncludeRiskScore {
		base.IncludeRiskScore = true
	}
	if override.IncludeRuleIDs {
		base.IncludeRuleIDs = true
	}
	if override.IncludeFindingMessages {
		base.IncludeFindingMessages = true
	}
	if override.IncludeValues {
		base.IncludeValues = true
	}
	if override.IncludeActions {
		base.IncludeActions = true
	}
	if override.IncludeEvidence {
		base.IncludeEvidence = true
	}
	if override.IncludeTrace {
		base.IncludeTrace = true
	}
	if override.IncludeHeaders {
		base.IncludeHeaders = true
	}
	if override.SupportMessage != "" {
		base.SupportMessage = override.SupportMessage
	}
	if override.SupportURL != "" {
		base.SupportURL = override.SupportURL
	}
	if override.CodePrefix != "" {
		base.CodePrefix = override.CodePrefix
	}
	if len(override.RedactFields) > 0 {
		base.RedactFields = override.RedactFields
	}
	if override.MaxDetails > 0 {
		base.MaxDetails = override.MaxDetails
	}
	return base
}

func publicEffectMessage(decision Decision) string {
	switch decision.Effect {
	case DecisionDeny, DecisionBlock:
		return "Request blocked by security policy."
	case DecisionThrottle:
		return "Request rate limit exceeded."
	case DecisionChallenge:
		return "Additional verification is required."
	case DecisionRevoke:
		return "Access was revoked by security policy."
	case DecisionEscalate:
		return "Request was escalated for security review."
	case DecisionMonitor:
		if decision.Allowed {
			return "Request allowed with security monitoring."
		}
		return "Request monitored by security policy."
	default:
		if decision.Allowed {
			return "Request allowed."
		}
		return "Request was not allowed."
	}
}

func publicDecisionDescription(sec *Context, decision Decision, policy ResponseMessagePolicy) string {
	policy = normalizeResponsePolicy(policy)
	if policy.DetailLevel == ResponseDetailsFull && strings.TrimSpace(decision.Explanation) != "" {
		return sanitizePublicText(decision.Explanation, policy)
	}
	parts := []string{}
	if reason := topPublicReason(sec, decision, policy); reason != "" {
		parts = append(parts, reason)
	}
	if policy.SupportMessage != "" && !decision.Allowed {
		parts = append(parts, policy.SupportMessage)
	}
	if len(parts) == 0 {
		return publicEffectMessage(decision)
	}
	return strings.Join(parts, " ")
}

func topPublicReason(_ *Context, decision Decision, policy ResponseMessagePolicy) string {
	for _, finding := range decision.Findings {
		if finding.Message != "" && policy.IncludeFindingMessages {
			return sanitizePublicText(finding.Message, policy)
		}
		if finding.Type != "" {
			return "Reason category: " + humanizeToken(finding.Type) + "."
		}
		if finding.ID != "" {
			return "Reason category: " + humanizeToken(finding.ID) + "."
		}
	}
	if len(decision.MatchedRules) > 0 && policy.IncludeRuleIDs {
		return "Matched policy rule: " + sanitizePublicText(decision.MatchedRules[0], policy) + "."
	}
	if decision.Severity != "" {
		return "Security severity: " + string(decision.Severity) + "."
	}
	return ""
}

func publicDecisionDetails(_ *Context, decision Decision, policy ResponseMessagePolicy) []map[string]any {
	var details []map[string]any
	add := func(m map[string]any) {
		if len(details) < policy.MaxDetails {
			details = append(details, m)
		}
	}
	if policy.IncludeRuleIDs && len(decision.MatchedRules) > 0 {
		add(map[string]any{"type": "matched_rules", "values": sanitizeStringSlice(decision.MatchedRules, policy)})
	}
	if policy.IncludeFindingMessages || policy.IncludeValues || policy.DetailLevel == ResponseDetailsFull {
		for _, f := range decision.Findings {
			m := map[string]any{"type": "finding", "id": f.ID, "category": firstNonEmpty(f.Type, f.ID), "severity": f.Severity, "risk": f.Risk}
			if policy.IncludeFindingMessages && f.Message != "" {
				m["message"] = sanitizePublicText(f.Message, policy)
			}
			if policy.IncludeValues && len(f.Fields) > 0 {
				m["fields"] = sanitizeMap(f.Fields, policy)
			}
			add(m)
		}
	}
	if policy.IncludeActions {
		for _, action := range decision.Actions {
			m := map[string]any{"type": "action", "id": action.ID, "status": action.Status}
			if action.Type != "" {
				m["action_type"] = action.Type
			}
			if action.Error != "" && policy.DetailLevel == ResponseDetailsFull {
				m["error"] = sanitizePublicText(action.Error, policy)
			}
			add(m)
		}
	}
	if policy.IncludeEvidence {
		for _, evidence := range decision.Evidence {
			m := map[string]any{"type": "evidence", "category": evidence.Type, "id": evidence.ID}
			if evidence.Message != "" {
				m["message"] = sanitizePublicText(evidence.Message, policy)
			}
			if policy.IncludeValues && len(evidence.Fields) > 0 {
				m["fields"] = sanitizeMap(evidence.Fields, policy)
			}
			add(m)
		}
	}
	return details
}

func publicDecisionCode(policy ResponseMessagePolicy, decision Decision) string {
	sev := strings.ToUpper(string(decision.Severity))
	if sev == "" {
		sev = "INFO"
	}
	return strings.ToUpper(policy.CodePrefix) + "_" + strings.ToUpper(string(decision.Effect)) + "_" + sev
}

func sanitizeMap(in map[string]any, policy ResponseMessagePolicy) map[string]any {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]any, len(in))
	for _, key := range keys {
		if isSensitiveField(key, policy.RedactFields) {
			out[key] = "<redacted>"
			continue
		}
		out[key] = sanitizeValue(in[key], policy)
	}
	return out
}

func sanitizeValue(v any, policy ResponseMessagePolicy) any {
	if !policy.IncludeValues {
		return nil
	}
	switch x := v.(type) {
	case string:
		if isLikelySecretValue(x) {
			return "<redacted>"
		}
		return sanitizePublicText(x, policy)
	case []string:
		return sanitizeStringSlice(x, policy)
	case map[string]any:
		return sanitizeMap(x, policy)
	default:
		return x
	}
}

func sanitizeStringSlice(values []string, policy ResponseMessagePolicy) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, sanitizePublicText(value, policy))
	}
	return out
}

func sanitizePublicText(value string, policy ResponseMessagePolicy) string {
	value = strings.TrimSpace(strings.Join(strings.Fields(value), " "))
	if value == "" {
		return value
	}
	if policy.Environment == EnvironmentProduction || !policy.IncludeValues {
		value = redactTokens(value, policy)
	}
	return value
}

func redactTokens(value string, policy ResponseMessagePolicy) string {
	fields := policy.RedactFields
	parts := strings.Fields(value)
	for i, part := range parts {
		lower := strings.ToLower(strings.Trim(part, " .,:;()[]{}\"'"))
		if isSensitiveField(lower, fields) || strings.Contains(lower, "=") && isSensitiveField(strings.SplitN(lower, "=", 2)[0], fields) {
			parts[i] = "<redacted>"
			continue
		}
		if isLikelySecretValue(lower) {
			parts[i] = "<redacted>"
		}
	}
	return strings.Join(parts, " ")
}

func isSensitiveField(key string, fields []string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	for _, field := range fields {
		f := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(field), "-", "_"))
		if f != "" && strings.Contains(key, f) {
			return true
		}
	}
	return false
}

func isLikelySecretValue(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) >= 24 && strings.Count(v, ".") >= 2 {
		return true
	}
	if strings.HasPrefix(strings.ToLower(v), "bearer") {
		return true
	}
	if len(v) >= 32 {
		_, err := hex.DecodeString(strings.Trim(v, " .,:;()[]{}\"'"))
		if err == nil {
			return true
		}
	}
	return false
}

func headerSafeMessage(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 180 {
		value = value[:177] + "..."
	}
	return value
}

func humanizeToken(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

func publicValueHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
