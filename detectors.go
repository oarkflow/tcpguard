package tcpguard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	condition "github.com/oarkflow/tcpguard/internal/ruleexpr"
)

type DetectorFunc struct {
	Name string
	Fn   func(context.Context, *Context, Event) ([]Finding, error)
}

func (d DetectorFunc) ID() string { return d.Name }
func (d DetectorFunc) Detect(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	return d.Fn(ctx, sec, event)
}

func DefaultDetectors(store SecurityStore, secretProvider func(*Context) []byte) []Detector {
	return DefaultDetectorsWithRateAlgorithm(store, secretProvider, RateFixedWindow)
}

func DefaultDetectorsWithRateAlgorithm(store SecurityStore, secretProvider func(*Context) []byte, algorithm RateAlgorithm) []Detector {
	return DefaultDetectorsWithSafety(store, secretProvider, algorithm, false)
}

// DefaultDetectorsWithSafety returns the built-in detectors with optional
// mandatory request-signature enforcement.
func DefaultDetectorsWithSafety(store SecurityStore, secretProvider func(*Context) []byte, algorithm RateAlgorithm, requireSignature bool) []Detector {
	replay := NewReplayDetector(store, secretProvider)
	replay.RequireSignature = requireSignature
	// Presence of an Idempotency-Key is sufficient to activate duplicate-key
	// detection; the builder controls whether the key is mandatory.
	replay.RequireIdempotency = true
	return []Detector{
		HeaderAnomalyDetector{},
		SensitiveEndpointDetector{},
		replay,
		NewRateDetectorWithAlgorithm(store, algorithm),
		SessionDriftDetector{},
		BusinessAnomalyDetector{},
	}
}

func detectorShouldRun(detector Detector, sec *Context, event Event) bool {
	if detector == nil || sec == nil {
		return false
	}
	switch detector.(type) {
	case HeaderAnomalyDetector:
		return strings.HasPrefix(event.Type, "request.") || event.Type == ""
	case SensitiveEndpointDetector:
		return sec.Request.Path != "" && (strings.HasPrefix(event.Type, "request.") || event.Type == "")
	case ReplayDetector:
		if sec.Raw != nil || len(sec.Request.Headers) > 0 {
			return securityHeader(sec, "X-TCPGuard-Nonce") != "" ||
				securityHeader(sec, "X-TCPGuard-Timestamp") != "" ||
				securityHeader(sec, "X-TCPGuard-Signature") != "" ||
				securityHeader(sec, "X-Signature") != "" ||
				securityHeader(sec, "X-API-Key") != "" ||
				securityHeader(sec, "Idempotency-Key") != ""
		}
		return len(sec.Security) > 0
	case RateDetector:
		return strings.HasPrefix(event.Type, "request.") || event.Type == ""
	case SessionDriftDetector:
		return sec.Session.ID != "" || sec.Session.PreviousCountry != "" || sec.Session.UserAgent != "" || sec.Session.NewDevice || strings.HasPrefix(event.Type, "auth.")
	case BusinessAnomalyDetector:
		return sec.Business.Action != "" || sec.Business.Workflow != "" || sec.Business.Amount != 0 || sec.Business.OutsideHours || sec.Business.Sensitivity != ""
	case AbuseDetector:
		return strings.HasPrefix(event.Type, "request.") ||
			strings.HasPrefix(event.Type, "auth.") ||
			sec.Identity.ID != "" ||
			sec.Network.IP != "" ||
			sec.Business.Action != "" ||
			sec.Business.Amount != 0
	default:
		return true
	}
}

func detectorNeedsTimeout(detector Detector) bool {
	switch detector.(type) {
	case HeaderAnomalyDetector, SensitiveEndpointDetector, ReplayDetector, RateDetector, SessionDriftDetector, BusinessAnomalyDetector, AbuseDetector:
		return false
	default:
		return true
	}
}

type HeaderAnomalyDetector struct{}

func (HeaderAnomalyDetector) ID() string { return "header-anomaly" }
func (HeaderAnomalyDetector) Detect(_ context.Context, sec *Context, _ Event) ([]Finding, error) {
	var out []Finding
	if sec.Request.Host == "" {
		setContextFact(sec, "security.host_missing", true)
		out = append(out, finding("missing_host_header", 30, "request is missing Host header"))
	}
	if sec.Request.ContentType != "" && sec.Request.Method == http.MethodPost && !strings.Contains(sec.Request.ContentType, "json") && !strings.Contains(sec.Request.ContentType, "form") {
		setContextFact(sec, "security.content_type_unusual", true)
		out = append(out, finding("content_type_unusual", 20, "unusual POST content type"))
	}
	if strings.Contains(strings.ToLower(sec.Request.UserAgent), "sqlmap") || sec.Request.UserAgent == "" {
		setContextFact(sec, "security.suspicious_user_agent", true)
		out = append(out, finding("suspicious_user_agent", 35, "suspicious or missing user agent"))
	}
	if sec.Request.Origin != "" && sec.Request.Referer != "" && !sameOrigin(sec.Request.Origin, sec.Request.Referer) {
		setContextFact(sec, "security.origin_referer_mismatch", true)
		out = append(out, finding("origin_referer_mismatch", 25, "origin and referer do not match"))
	}
	if hasForwardedRequestHeaders(sec.Request.Headers) && factBool(sec, "security.forwarded_headers_untrusted") {
		out = append(out, finding("untrusted_forwarded_headers", 75, "forwarded client identity headers came from an untrusted peer"))
	}
	if hasHeader(sec.Request.Headers, "Content-Length") && hasHeader(sec.Request.Headers, "Transfer-Encoding") {
		out = append(out, finding("ambiguous_request_framing", 90, "request contains both Content-Length and Transfer-Encoding"))
	}
	if hasHeader(sec.Request.Headers, "X-HTTP-Method-Override") || hasHeader(sec.Request.Headers, "X-Method-Override") {
		setContextFact(sec, "security.method_override_header", true)
		out = append(out, finding("method_override_header", 55, "request uses an HTTP method override header"))
	}
	if sec.Request.Method == http.MethodTrace || sec.Request.Method == http.MethodConnect {
		setContextFact(sec, "security.dangerous_http_method", true)
		out = append(out, finding("dangerous_http_method", 65, "TRACE or CONNECT is not suitable for this application endpoint"))
	}
	if containsAny(sec.Request.EscapedPath, "%00", "%2f", "%2F", "%5c", "%5C") || strings.Contains(sec.Request.Path, ";") {
		setContextFact(sec, "security.path_canonicalization_ambiguity", true)
		out = append(out, finding("path_canonicalization_ambiguity", 70, "request path contains an encoded separator, null byte, or matrix parameter"))
	}
	if value := headerValue(sec.Request.Headers, "Content-Length"); strings.Contains(value, ",") {
		setContextFact(sec, "security.duplicate_content_length", true)
		out = append(out, finding("duplicate_content_length", 90, "request contains multiple Content-Length values"))
	}
	if value := headerValue(sec.Request.Headers, "Transfer-Encoding"); value != "" && !strings.EqualFold(strings.TrimSpace(value), "chunked") {
		setContextFact(sec, "security.invalid_transfer_encoding", true)
		out = append(out, finding("invalid_transfer_encoding", 85, "request uses an unsupported Transfer-Encoding value"))
	}
	if value := headerValue(sec.Request.Headers, "Range"); strings.Count(value, ",") >= 2 {
		setContextFact(sec, "security.range_request_abuse", true)
		out = append(out, finding("range_request_abuse", 55, "request contains too many byte ranges"))
	}
	if value := headerValue(sec.Request.Headers, "Content-Encoding"); value != "" && !strings.EqualFold(strings.TrimSpace(value), "identity") && !strings.EqualFold(strings.TrimSpace(value), "gzip") {
		setContextFact(sec, "security.unsupported_content_encoding", true)
		out = append(out, finding("unsupported_content_encoding", 60, "request uses an unsupported content encoding"))
	}
	if factBool(sec, "security.csrf_missing") {
		out = append(out, finding("csrf_token_missing", 85, "cross-origin cookie request has no CSRF token"))
	}
	if factBool(sec, "security.idempotency_missing") {
		out = append(out, finding("idempotency_key_missing", 65, "sensitive mutation has no idempotency key"))
	}
	if factBool(sec, "security.cors_origin_not_allowed") {
		out = append(out, finding("cors_origin_not_allowed", 80, "request Origin is outside the configured CORS allowlist"))
	}
	if paginationAbuse(sec) {
		setContextFact(sec, "security.pagination_abuse", true)
		out = append(out, finding("pagination_abuse", 55, "pagination or result-size parameter exceeds the safe limit"))
	}
	if isJSONRequest(sec) && sec.Raw != nil {
		if depth, duplicate, malformed := jsonBodyComplexity(sec.Raw); malformed {
			setContextFact(sec, "security.malformed_json", true)
			out = append(out, finding("malformed_json", 60, "request JSON is malformed"))
		} else if duplicate {
			setContextFact(sec, "security.duplicate_json_key", true)
			out = append(out, finding("duplicate_json_key", 75, "request JSON contains duplicate object keys"))
		} else if depth > 50 {
			setContextFact(sec, "security.json_complexity_abuse", true)
			out = append(out, finding("json_complexity_abuse", 70, "request JSON nesting is excessive"))
		}
	}
	for _, item := range []struct {
		fact, id, message string
		risk              float64
	}{
		{"security.https_required", "https_required", "request is not protected by HTTPS", 85},
		{"security.host_not_allowed", "host_not_allowed", "request Host is outside the configured allowlist", 85},
		{"security.method_not_allowed", "method_not_allowed", "request method is outside the configured allowlist", 75},
		{"security.headers_oversized", "headers_oversized", "request headers exceed the configured byte limit", 75},
		{"security.header_count_exceeded", "header_count_exceeded", "request contains too many headers", 75},
		{"security.url_oversized", "url_oversized", "request URI exceeds the configured limit", 75},
		{"security.body_oversized", "body_oversized", "request body exceeds the configured limit", 75},
	} {
		if factBool(sec, item.fact) {
			out = append(out, finding(item.id, item.risk, item.message))
		}
	}
	return out, nil
}

func factBool(sec *Context, path string) bool {
	if sec == nil {
		return false
	}
	sec.rebuildFacts()
	v, ok := sec.Facts.Get(path)
	b, _ := v.(bool)
	return ok && b
}

func hasHeader(headers map[string]string, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func hasForwardedRequestHeaders(headers map[string]string) bool {
	for key := range headers {
		switch strings.ToLower(key) {
		case "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "x-original-url", "x-rewrite-url":
			return true
		}
	}
	return false
}

func paginationAbuse(sec *Context) bool {
	for _, key := range []string{"limit", "page_size", "pagesize", "offset"} {
		value := strings.TrimSpace(sec.Request.Query[key])
		if value == "" {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err == nil && ((key == "offset" && n > 100000) || (key != "offset" && n > 1000)) {
			return true
		}
	}
	return false
}

func isJSONRequest(sec *Context) bool {
	return strings.Contains(strings.ToLower(sec.Request.ContentType), "json")
}

func jsonBodyComplexity(r *http.Request) (int, bool, bool) {
	if r.Body == nil {
		return 0, false, false
	}
	const maxInspectBytes = 2 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInspectBytes+1))
	if len(body) > maxInspectBytes {
		// Preserve the complete unread request stream for downstream handlers.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		return 51, false, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return 0, false, true
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	depth, maxDepth := 0, 0
	type jsonFrame struct {
		object       bool
		expectingKey bool
		keys         map[string]struct{}
	}
	frames := make([]jsonFrame, 0, 8)
	duplicate := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return maxDepth, duplicate, false
		}
		if err != nil {
			return maxDepth, duplicate, true
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
				if depth > maxDepth {
					maxDepth = depth
				}
				frames = append(frames, jsonFrame{object: delimiter == '{', expectingKey: delimiter == '{', keys: map[string]struct{}{}})
			case '}', ']':
				depth--
				if len(frames) == 0 {
					return maxDepth, duplicate, true
				}
				frames = frames[:len(frames)-1]
				if len(frames) > 0 && frames[len(frames)-1].object {
					frames[len(frames)-1].expectingKey = true
				}
			}
			continue
		}
		if len(frames) > 0 && frames[len(frames)-1].object {
			frame := &frames[len(frames)-1]
			if frame.expectingKey {
				key, ok := token.(string)
				if !ok {
					return maxDepth, duplicate, true
				}
				if _, exists := frame.keys[key]; exists {
					duplicate = true
				}
				frame.keys[key] = struct{}{}
				frame.expectingKey = false
			} else {
				frame.expectingKey = true
			}
		}
	}
}

type SensitiveEndpointDetector struct {
	Patterns []string
}

func (d SensitiveEndpointDetector) ID() string { return "sensitive-endpoint" }
func (d SensitiveEndpointDetector) Detect(_ context.Context, sec *Context, _ Event) ([]Finding, error) {
	patterns := d.Patterns
	if len(patterns) == 0 {
		patterns = []string{"/admin/*", "/api/v1/reports/export", "/api/v1/users/*/permissions"}
	}
	for _, pattern := range patterns {
		if glob(pattern, sec.Request.Path) {
			setContextFact(sec, "endpoint.sensitive", true)
			setContextFact(sec, "endpoint.sensitivity_score", 30)
			return []Finding{finding("sensitive_endpoint_access", 30, "sensitive endpoint accessed")}, nil
		}
	}
	return nil, nil
}

type ReplayDetector struct {
	store              SecurityStore
	secretProvider     func(*Context) []byte
	ClockSkew          time.Duration
	NonceTTL           time.Duration
	RequireSignature   bool
	RequireIdempotency bool
}

func NewReplayDetector(store SecurityStore, secretProvider func(*Context) []byte) ReplayDetector {
	return ReplayDetector{store: store, secretProvider: secretProvider, ClockSkew: time.Minute, NonceTTL: 10 * time.Minute}
}

func (d ReplayDetector) ID() string { return "replay-mitm" }
func (d ReplayDetector) Detect(ctx context.Context, sec *Context, _ Event) ([]Finding, error) {
	var out []Finding
	if sec.Raw == nil {
		return nil, nil
	}
	nonce := securityHeader(sec, "X-TCPGuard-Nonce")
	if nonce != "" && d.store != nil {
		key := "nonce:" + nonce
		consumed := false
		if atomicStore, ok := d.store.(AtomicSecurityStore); ok {
			var err error
			consumed, err = atomicStore.SetNX(ctx, key, []byte("1"), d.NonceTTL)
			if err != nil {
				return nil, err
			}
		} else if _, found, err := d.store.Get(ctx, key); err != nil {
			return nil, err
		} else {
			consumed = !found
			if consumed {
				if err := d.store.Set(ctx, key, []byte("1"), d.NonceTTL); err != nil {
					return nil, err
				}
			}
		}
		if !consumed {
			sec.Security["nonce"] = map[string]any{"reused": true}
			setContextFact(sec, "security.nonce.reused", true)
			out = append(out, finding("nonce_reused", 85, "request nonce was already used"))
		} else {
			setContextFact(sec, "security.nonce.reused", false)
		}
	}
	if rawTS := securityHeader(sec, "X-TCPGuard-Timestamp"); rawTS != "" {
		ts, err := strconv.ParseInt(rawTS, 10, 64)
		if err == nil {
			skew := time.Since(time.Unix(ts, 0))
			if skew < 0 {
				skew = -skew
			}
			sec.Security["timestamp"] = map[string]any{"skew_seconds": skew.Seconds()}
			setContextFact(sec, "security.timestamp.skew_seconds", skew.Seconds())
			if skew > d.ClockSkew {
				out = append(out, finding("timestamp_skew", 65, "request timestamp is outside allowed clock skew"))
			}
		}
	}
	secret := []byte(nil)
	if d.secretProvider != nil {
		secret = d.secretProvider(sec)
	}
	if len(secret) > 0 {
		if d.RequireSignature && securityHeader(sec, "X-TCPGuard-Signature") == "" {
			setContextFact(sec, "security.signature.valid", false)
			out = append(out, finding("missing_signature", 90, "request signature is required"))
			return out, nil
		}
		if got := securityHeader(sec, "X-TCPGuard-Signature"); got != "" && sec.Raw.Header.Get("X-TCPGuard-Signature") == "" {
			sec.Raw.Header.Set("X-TCPGuard-Signature", got)
		}
		valid, err := validateHMAC(sec.Raw, secret)
		if err != nil {
			return nil, err
		}
		sec.Security["signature"] = map[string]any{"valid": valid}
		setContextFact(sec, "security.signature.valid", valid)
		if !valid {
			out = append(out, finding("invalid_signature", 90, "request signature is invalid"))
		}
	}
	if d.RequireIdempotency && isMutationMethod(sec.Request.Method) {
		if err := d.detectIdempotency(ctx, sec); err != nil {
			return nil, err
		}
		if factBool(sec, "security.idempotency_conflict") {
			out = append(out, finding("idempotency_conflict", 90, "idempotency key was reused with a different request body"))
		} else if factBool(sec, "security.idempotency_reused") {
			out = append(out, finding("idempotency_reused", 75, "idempotency key was already used"))
		}
	}
	return out, nil
}

func (d ReplayDetector) detectIdempotency(ctx context.Context, sec *Context) error {
	key := strings.TrimSpace(securityHeader(sec, "Idempotency-Key"))
	if key == "" || d.store == nil {
		return nil
	}
	scope := firstNonEmpty(sec.Identity.ID, sec.Session.ID, sec.Network.IP)
	if scope == "" {
		scope = "anonymous"
	}
	bodyHash := ""
	if sec.Raw != nil && sec.Raw.Body != nil {
		body, err := io.ReadAll(sec.Raw.Body)
		if err != nil {
			return err
		}
		sec.Raw.Body = io.NopCloser(bytes.NewReader(body))
		sum := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(sum[:])
	}
	storeKey := "idempotency:" + stableKey(scope+":"+key)
	atomicStore, ok := d.store.(AtomicSecurityStore)
	if !ok {
		return nil
	}
	created, err := atomicStore.SetNX(ctx, storeKey, []byte(bodyHash), 24*time.Hour)
	if err != nil {
		return err
	}
	if created {
		return nil
	}
	setContextFact(sec, "security.idempotency_reused", true)
	if previous, found, getErr := d.store.Get(ctx, storeKey); getErr != nil {
		return getErr
	} else if found && string(previous) != bodyHash {
		setContextFact(sec, "security.idempotency_conflict", true)
	}
	if factBool(sec, "security.idempotency_conflict") {
		return nil
	}
	return nil
}

func isMutationMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func securityHeader(sec *Context, key string) string {
	if sec == nil {
		return ""
	}
	if sec.Raw != nil {
		if value := sec.Raw.Header.Get(key); value != "" {
			return value
		}
	}
	for gotKey, value := range sec.Request.Headers {
		if strings.EqualFold(gotKey, key) {
			return value
		}
	}
	return ""
}

type RateDetector struct {
	store               SecurityStore
	Algorithm           RateAlgorithm
	IPLimit             int64
	UserLimit           int64
	TenantLimit         int64
	SessionLimit        int64
	EndpointLimit       int64
	IPUserLimit         int64
	TenantEndpointLimit int64
	Window              time.Duration
}

func NewRateDetector(store SecurityStore) RateDetector {
	return NewRateDetectorWithAlgorithm(store, RateFixedWindow)
}

func NewRateDetectorWithAlgorithm(store SecurityStore, algorithm RateAlgorithm) RateDetector {
	if algorithm == "" {
		algorithm = RateFixedWindow
	}
	return RateDetector{store: store, Algorithm: algorithm, IPLimit: 120, UserLimit: 300, TenantLimit: 5000, Window: time.Minute}
}

func (d RateDetector) ID() string { return "rate-abuse" }
func (d RateDetector) Detect(ctx context.Context, sec *Context, _ Event) ([]Finding, error) {
	if d.store == nil {
		return nil, nil
	}
	var out []Finding
	out = d.checkDimension(ctx, sec, out, "ip", sec.Network.IP, d.IPLimit, "rate_limit_abuse", "IP request rate exceeded")
	out = d.checkDimension(ctx, sec, out, "user", sec.Identity.ID, d.UserLimit, "user_rate_limit_abuse", "user request rate exceeded")
	tenant := sec.Tenant.ID
	if tenant == "" {
		tenant = sec.Identity.Tenant
	}
	out = d.checkDimension(ctx, sec, out, "tenant", tenant, d.TenantLimit, "tenant_rate_limit_abuse", "tenant request rate exceeded")
	out = d.checkDimension(ctx, sec, out, "session", sec.Session.ID, d.SessionLimit, "session_rate_limit_abuse", "session request rate exceeded")
	out = d.checkDimension(ctx, sec, out, "endpoint", sec.Request.Method+" "+sec.Request.Path, d.EndpointLimit, "endpoint_rate_limit_abuse", "endpoint request rate exceeded")
	out = d.checkDimension(ctx, sec, out, "ip_user", sec.Network.IP+"|"+sec.Identity.ID, d.IPUserLimit, "ip_user_rate_limit_abuse", "IP and user request rate exceeded")
	out = d.checkDimension(ctx, sec, out, "tenant_endpoint", tenant+"|"+sec.Request.Method+" "+sec.Request.Path, d.TenantEndpointLimit, "tenant_endpoint_rate_limit_abuse", "tenant endpoint request rate exceeded")
	return out, nil
}

func (d RateDetector) checkDimension(ctx context.Context, sec *Context, out []Finding, dimension, value string, limit int64, findingID, message string) []Finding {
	if value == "" || strings.HasPrefix(value, "|") || strings.HasSuffix(value, "|") {
		return out
	}
	n, err := d.count(ctx, "rate:"+dimension+":"+value, limit)
	if err != nil {
		return append(out, finding("rate_detector_error", 10, err.Error()))
	}
	setRate(sec, dimension, n)
	if limit > 0 && n > limit {
		return append(out, finding(findingID, 70, message))
	}
	return out
}

func (d RateDetector) count(ctx context.Context, key string, limit int64) (int64, error) {
	switch d.Algorithm {
	case RateSlidingWindow:
		return d.slidingWindowCount(ctx, key)
	case RateTokenBucket:
		return d.tokenBucketCount(ctx, key, limit)
	default:
		return d.store.Incr(ctx, key, d.Window)
	}
}

type slidingWindowState struct {
	CurrentStart  int64 `json:"current_start"`
	CurrentCount  int64 `json:"current_count"`
	PreviousStart int64 `json:"previous_start"`
	PreviousCount int64 `json:"previous_count"`
}

func (d RateDetector) slidingWindowCount(ctx context.Context, key string) (int64, error) {
	now := time.Now()
	window := d.Window
	if window <= 0 {
		window = time.Minute
	}
	start := now.UnixNano() / window.Nanoseconds() * window.Nanoseconds()
	var state slidingWindowState
	if data, found, err := d.store.Get(ctx, key+":sliding"); err != nil {
		return 0, err
	} else if found {
		_ = json.Unmarshal(data, &state)
	}
	if state.CurrentStart != start {
		if state.CurrentStart == start-window.Nanoseconds() {
			state.PreviousStart = state.CurrentStart
			state.PreviousCount = state.CurrentCount
		} else {
			state.PreviousStart = 0
			state.PreviousCount = 0
		}
		state.CurrentStart = start
		state.CurrentCount = 0
	}
	state.CurrentCount++
	weight := float64(window.Nanoseconds()-(now.UnixNano()-start)) / float64(window.Nanoseconds())
	estimate := state.CurrentCount + int64(math.Ceil(float64(state.PreviousCount)*weight))
	data, _ := json.Marshal(state)
	return estimate, d.store.Set(ctx, key+":sliding", data, 2*window)
}

type tokenBucketState struct {
	Tokens     float64 `json:"tokens"`
	LastRefill int64   `json:"last_refill"`
	Requests   int64   `json:"requests"`
}

func (d RateDetector) tokenBucketCount(ctx context.Context, key string, limit int64) (int64, error) {
	if limit <= 0 {
		limit = 1
	}
	window := d.Window
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now()
	capacity := float64(limit)
	ratePerSecond := capacity / window.Seconds()
	state := tokenBucketState{Tokens: capacity, LastRefill: now.UnixNano()}
	if data, found, err := d.store.Get(ctx, key+":bucket"); err != nil {
		return 0, err
	} else if found {
		_ = json.Unmarshal(data, &state)
	}
	elapsed := now.Sub(time.Unix(0, state.LastRefill)).Seconds()
	if elapsed > 0 {
		state.Tokens += elapsed * ratePerSecond
		if state.Tokens > capacity {
			state.Tokens = capacity
		}
		state.LastRefill = now.UnixNano()
	}
	if state.Tokens >= 1 {
		state.Tokens--
		state.Requests = limit - int64(math.Floor(state.Tokens))
	} else {
		state.Requests = limit + 1
	}
	data, _ := json.Marshal(state)
	return state.Requests, d.store.Set(ctx, key+":bucket", data, 2*window)
}

type SessionDriftDetector struct{}

func (SessionDriftDetector) ID() string { return "session-drift" }
func (SessionDriftDetector) Detect(_ context.Context, sec *Context, event Event) ([]Finding, error) {
	var out []Finding
	if sec.Session.PreviousCountry != "" && sec.Network.Country != "" && sec.Session.PreviousCountry != sec.Network.Country {
		sec.Session.CountryChanged = true
		setContextFact(sec, "session.country_changed", true)
		out = append(out, finding("session_country_changed", 65, "session country changed"))
	}
	if sec.Session.UserAgent != "" && sec.Request.UserAgent != "" && sec.Session.UserAgent != sec.Request.UserAgent {
		sec.Session.UserAgentChanged = true
		setContextFact(sec, "session.user_agent_changed", true)
		out = append(out, finding("session_user_agent_changed", 45, "session user agent changed"))
	}
	if event.Type == "auth.login_success" && sec.Session.NewDevice {
		out = append(out, finding("new_device_login", 45, "login from a new device"))
	}
	return out, nil
}

type BusinessAnomalyDetector struct{}

func (BusinessAnomalyDetector) ID() string { return "business-anomaly" }
func (BusinessAnomalyDetector) Detect(_ context.Context, sec *Context, _ Event) ([]Finding, error) {
	var out []Finding
	if sec.Business.OutsideHours && (sec.Identity.Role == "admin" || sec.Identity.Role == "super_admin") {
		out = append(out, finding("after_hours_admin_access", 50, "admin activity outside business hours"))
	}
	if strings.Contains(sec.Business.Action, "export") && sec.Business.Sensitivity == "high" {
		out = append(out, finding("sensitive_export", 55, "sensitive business export"))
	}
	if sec.Business.Amount >= 1000000 {
		out = append(out, finding("high_value_action", 60, "high-value business action"))
	}
	return out, nil
}

type DSLDetector struct {
	Definition DetectorDefinition
	compiled   []*condition.Expression
}

func (d DSLDetector) ID() string { return d.Definition.ID }

func (d DSLDetector) Detect(ctx context.Context, sec *Context, _ Event) ([]Finding, error) {
	var out []Finding
	for path, value := range d.Definition.Outputs {
		setContextFact(sec, path, renderStructuredValue(value, sec, Decision{}))
	}
	for _, spec := range d.Definition.Findings {
		if spec.Condition != "" {
			expr, err := condition.Compile(normalizeCondition(spec.Condition))
			if err != nil {
				return nil, err
			}
			res, err := expr.Eval(ctx, sec.Facts)
			if err != nil || !res.Matched {
				continue
			}
		}
		risk := spec.Risk
		if risk <= 0 {
			risk = 30
		}
		msg := spec.Message
		if msg == "" {
			msg = spec.ID + " detected"
		}
		f := finding(spec.ID, risk, msg)
		f.Fields = spec.Fields
		out = append(out, f)
	}
	return out, nil
}

type FileLookupEnricher struct {
	Definition EnricherDefinition
}

func (e FileLookupEnricher) ID() string { return e.Definition.ID }

func (e FileLookupEnricher) Enrich(ctx context.Context, sec *Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fields := strings.Fields(e.Definition.Source)
	if len(fields) != 2 || fields[0] != "file" {
		return nil
	}
	file, err := os.Open(fields[1])
	if err != nil {
		return err
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return err
	}
	if len(rows) < 2 {
		return nil
	}
	headers := rows[0]
	keyValue := stringifyValueForPath(sec, e.Definition.Key)
	for _, row := range rows[1:] {
		record := map[string]string{}
		for i, header := range headers {
			if i < len(row) {
				record[header] = row[i]
			}
		}
		sourceKey := strings.TrimPrefix(e.Definition.Key, "record.")
		if sourceKey == e.Definition.Key {
			if i := strings.LastIndexByte(e.Definition.Key, '.'); i >= 0 {
				sourceKey = e.Definition.Key[i+1:]
			}
		}
		if record[sourceKey] != keyValue {
			continue
		}
		for from, to := range e.Definition.Fields {
			setContextFact(sec, to, record[from])
		}
		return nil
	}
	return nil
}

type BaselineDetector struct {
	Definition BaselineDefinition
	Store      SecurityStore
}

func (d BaselineDetector) ID() string { return "baseline-" + d.Definition.ID }

func (d BaselineDetector) Detect(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	if d.Store == nil || d.Definition.ID == "" || d.Definition.Observe != event.Type {
		return nil, nil
	}
	entity := stringifyValueForPath(sec, d.Definition.Entity)
	if entity == "" {
		return nil, nil
	}
	key := "baseline:" + d.Definition.ID + ":" + entity
	snapshot := BaselineSnapshot{Values: map[string]BaselineValue{}}
	if data, found, err := d.Store.Get(ctx, key); err != nil {
		return nil, err
	} else if found {
		_ = json.Unmarshal(data, &snapshot)
	}
	if snapshot.Values == nil {
		snapshot.Values = map[string]BaselineValue{}
	}
	var out []Finding
	minSamples := d.Definition.MinSamples
	if minSamples <= 0 {
		minSamples = 20
	}
	for alias, path := range d.Definition.Fields {
		value, ok := numericBaselineValue(sec, path)
		if !ok {
			continue
		}
		stats := snapshot.Values[alias]
		if stats.Count >= int64(minSamples) && stats.M2 > 0 {
			variance := stats.M2 / float64(stats.Count-1)
			if variance > 0 {
				z := (value - stats.Mean) / math.Sqrt(variance)
				if z < 0 {
					z = -z
				}
				setContextFact(sec, "baseline."+d.Definition.ID+"."+alias+"_zscore", z)
				if z >= 3 {
					out = append(out, finding("baseline_"+alias+"_anomaly", 45, "baseline deviation detected"))
				}
			}
		}
		stats.Count++
		delta := value - stats.Mean
		stats.Mean += delta / float64(stats.Count)
		stats.M2 += delta * (value - stats.Mean)
		snapshot.Values[alias] = stats
	}
	data, _ := json.Marshal(snapshot)
	ttl := d.Definition.Window
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	return out, d.Store.Set(ctx, key, data, ttl)
}

func setContextFact(sec *Context, path string, value any) {
	if sec.Extra == nil {
		sec.Extra = condition.MapFacts{}
	}
	if sec.Facts == nil {
		sec.Facts = condition.MapFacts{}
	}
	setFact(sec.Extra, path, value)
	setFact(sec.Facts, path, value)
}

func stringifyValueForPath(sec *Context, path string) string {
	if sec == nil || path == "" {
		return ""
	}
	if strings.HasPrefix(path, "record.") {
		return ""
	}
	sec.rebuildFacts()
	if value, ok := sec.Facts.Get(path); ok {
		return stringify(value)
	}
	return ""
}

func numericBaselineValue(sec *Context, path string) (float64, bool) {
	if path == "timestamp.hour" || path == "runtime.timestamp.hour" {
		t := sec.Runtime.Timestamp
		if t.IsZero() {
			t = time.Now()
		}
		return float64(t.Hour()), true
	}
	sec.rebuildFacts()
	if value, ok := sec.Facts.Get(path); ok {
		return number(value)
	}
	return 0, false
}

type HTTPDetector struct {
	Definition DetectorDefinition
	Client     *http.Client
}

func (d HTTPDetector) ID() string { return d.Definition.ID }

func (d HTTPDetector) Detect(ctx context.Context, sec *Context, _ Event) ([]Finding, error) {
	if d.Definition.Endpoint == "" {
		return nil, nil
	}
	timeout := d.Definition.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload, _ := json.Marshal(sec.Facts)
	method := d.Definition.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(callCtx, method, renderString(d.Definition.Endpoint, sec, Decision{}), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if d.Definition.Fallback == "allow" {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		if d.Definition.Fallback == "allow" {
			return nil, nil
		}
		return nil, err
	}
	for key, value := range body {
		setContextFact(sec, "ml."+key, value)
	}
	if score, ok := number(body["risk_score"]); ok && score > 0 {
		return []Finding{finding(firstNonEmpty(d.Definition.ID, "http_detector"), score, "external detector reported risk")}, nil
	}
	return nil, nil
}

func finding(id string, risk float64, message string) Finding {
	return Finding{ID: id, Type: id, Risk: risk, Confidence: 0.8, Severity: severityForRisk(risk), Message: message}
}

func setRate(sec *Context, entity string, n int64) {
	m, _ := sec.Rate[entity].(map[string]any)
	if m == nil {
		m = map[string]any{}
		sec.Rate[entity] = m
	}
	m["requests"] = n
	setContextFact(sec, "rate."+entity+".requests", n)
}

func sameOrigin(a, b string) bool {
	return originHost(a) == originHost(b)
}

func originHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func validateHMAC(r *http.Request, secret []byte) (bool, error) {
	got := r.Header.Get("X-TCPGuard-Signature")
	if got == "" {
		return false, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	mac := hmac.New(sha256.New, secret)
	if r.Header.Get("X-TCPGuard-Signature-Version") == "2" {
		bodyHash := sha256.Sum256(body)
		canonical := strings.Join([]string{
			"tcpguard-http-v2", r.Method, r.Host, r.URL.RequestURI(),
			r.Header.Get("X-TCPGuard-Timestamp"), r.Header.Get("X-TCPGuard-Nonce"),
			hex.EncodeToString(bodyHash[:]),
		}, "\n")
		_, _ = mac.Write([]byte(canonical))
	} else {
		// Version 1 is retained for compatibility with existing clients.
		_, _ = mac.Write([]byte(r.Method))
		_, _ = mac.Write([]byte("\n"))
		_, _ = mac.Write([]byte(r.URL.RequestURI()))
		_, _ = mac.Write([]byte("\n"))
		_, _ = mac.Write(body)
	}
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(strings.TrimPrefix(got, "sha256=")), []byte(want)), nil
}

func glob(pattern, value string) bool {
	matched, _ := compilePathPattern(pattern).Match(value)
	return matched
}

func matchPathPattern(pattern, value string) (bool, map[string]string) {
	return compilePathPattern(pattern).Match(value)
}

type pathPatternKind uint8

const (
	pathPatternExact pathPatternKind = iota
	pathPatternAny
	pathPatternPrefix
	pathPatternGlob
	pathPatternRoute
)

type pathPattern struct {
	raw      string
	kind     pathPatternKind
	prefix   string
	parts    []string
	segments []routeSegment
}

type routeSegment struct {
	literal string
	param   string
	star    bool
}

func compilePathPattern(pattern string) pathPattern {
	p := pathPattern{raw: pattern, kind: pathPatternExact}
	switch {
	case pattern == "*":
		p.kind = pathPatternAny
	case strings.Contains(pattern, ":") || strings.Contains(pattern, "{"):
		p.kind = pathPatternRoute
		rawSegments := splitPath(pattern)
		p.segments = make([]routeSegment, 0, len(rawSegments))
		for _, segment := range rawSegments {
			switch {
			case segment == "*":
				p.segments = append(p.segments, routeSegment{star: true})
			case strings.HasPrefix(segment, ":"):
				p.segments = append(p.segments, routeSegment{param: strings.TrimPrefix(segment, ":")})
			case strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}"):
				p.segments = append(p.segments, routeSegment{param: strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")})
			default:
				p.segments = append(p.segments, routeSegment{literal: segment})
			}
		}
	case strings.HasSuffix(pattern, "/*"):
		p.kind = pathPatternPrefix
		p.prefix = strings.TrimSuffix(pattern, "*")
	case strings.Contains(pattern, "*"):
		p.kind = pathPatternGlob
		p.parts = strings.Split(pattern, "*")
	}
	return p
}

func (p pathPattern) Match(value string) (bool, map[string]string) {
	switch p.kind {
	case pathPatternAny:
		return true, nil
	case pathPatternPrefix:
		return strings.HasPrefix(value, p.prefix), nil
	case pathPatternGlob:
		pos := 0
		for _, part := range p.parts {
			if part == "" {
				continue
			}
			idx := strings.Index(value[pos:], part)
			if idx < 0 {
				return false, nil
			}
			pos += idx + len(part)
		}
		return true, nil
	case pathPatternRoute:
		return p.matchRoute(value)
	default:
		return p.raw == value, nil
	}
}

func (p pathPattern) matchRoute(value string) (bool, map[string]string) {
	v := splitPath(value)
	params := map[string]string{}
	if len(p.segments) > 0 && p.segments[len(p.segments)-1].star && len(v) >= len(p.segments)-1 {
		// final wildcard consumes the remainder after any named parameters.
	} else if len(p.segments) != len(v) {
		return false, nil
	}
	for i, segment := range p.segments {
		if segment.star && i == len(p.segments)-1 {
			return true, params
		}
		if i >= len(v) {
			return false, nil
		}
		switch {
		case segment.star:
			continue
		case segment.param != "":
			if v[i] == "" {
				return false, nil
			}
			params[segment.param] = v[i]
		case segment.literal != v[i]:
			return false, nil
		}
	}
	return true, params
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func severityForRisk(score float64) Severity {
	switch {
	case score >= 90:
		return SeverityCritical
	case score >= 75:
		return SeverityHigh
	case score >= 50:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func errorResult(id string, err error) ActionResult {
	return ActionResult{ID: id, Status: "failed", Error: fmt.Sprint(err), At: time.Now().UTC()}
}
