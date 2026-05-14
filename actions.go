package tcpguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

type BuiltinActionExecutor struct {
	Store      SecurityStore
	Incidents  IncidentStore
	Definition map[string]ActionDefinition
	Client     *http.Client
}

func (e BuiltinActionExecutor) Execute(ctx context.Context, sec *Context, decision Decision, ref ActionRef) ActionResult {
	if err := ctx.Err(); err != nil {
		return errorResult(ref.ID, err)
	}
	def := e.Definition[ref.ID]
	actionType := def.Type
	if actionType == "" {
		actionType = ref.ID
	}
	result := ActionResult{ID: ref.ID, Type: actionType, Status: "ok", At: time.Now().UTC()}
	switch actionType {
	case "allow", "monitor", "audit", "add_risk_header", "throttle", "tarpit", "block", "captcha_challenge", "mfa_challenge", "reauthenticate", "sql", "command":
		return result
	case "delay":
		delay := durationArg(ref.Args, 0)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errorResult(ref.ID, ctx.Err())
			case <-timer.C:
			}
		}
		return result
	case "revoke_session":
		if e.Store != nil && sec.Session.ID != "" {
			_ = e.Store.Set(ctx, "revoke:session:"+sec.Session.ID, []byte("1"), durationArg(ref.Args, 24*time.Hour))
		}
		return result
	case "revoke_all_sessions":
		if e.Store != nil && sec.Identity.ID != "" {
			_ = e.Store.Set(ctx, "revoke:sessions:"+sec.Identity.ID, []byte("1"), durationArg(ref.Args, 24*time.Hour))
		}
		return result
	case "disable_api_key":
		if e.Store != nil && sec.Request.Headers["X-API-Key"] != "" {
			_ = e.Store.Set(ctx, "disable:apikey:"+sec.Request.Headers["X-API-Key"], []byte("1"), durationArg(ref.Args, 24*time.Hour))
		}
		return result
	case "lock_user":
		if e.Store != nil && sec.Identity.ID != "" {
			_ = e.Store.Set(ctx, "lock:user:"+sec.Identity.ID, []byte("1"), durationArg(ref.Args, 24*time.Hour))
		}
		return result
	case "ban_ip":
		if e.Store != nil && sec.Network.IP != "" {
			_ = e.Store.Set(ctx, "ban:ip:"+sec.Network.IP, []byte("1"), durationArg(ref.Args, 15*time.Minute))
		}
		return result
	case "ban_asn":
		if e.Store != nil && sec.Network.ASN != "" {
			_ = e.Store.Set(ctx, "ban:asn:"+sec.Network.ASN, []byte("1"), durationArg(ref.Args, 15*time.Minute))
		}
		return result
	case "block_country":
		if e.Store != nil && sec.Network.Country != "" {
			_ = e.Store.Set(ctx, "ban:country:"+sec.Network.Country, []byte("1"), durationArg(ref.Args, 15*time.Minute))
		}
		return result
	case "create_incident", "escalate_incident":
		incident := Incident{ID: "incident_" + sec.Request.ID + "_" + formatInt(time.Now().UnixNano()), Severity: decision.Severity, Status: "open", Summary: decision.Explanation, CreatedAt: result.At}
		result.ID = incident.ID
		if e.Incidents != nil {
			if err := e.Incidents.SaveIncident(ctx, incident); err != nil {
				return errorResult(ref.ID, err)
			}
		}
		return result
	case "webhook", "notify_admin", "notify_user", "notify_soc", "siem", "event_bus":
		endpoint := firstNonEmpty(def.Request.Endpoint, def.Endpoint)
		if endpoint == "" {
			result.Status = "skipped"
			result.Error = "no endpoint configured"
			return result
		}
		resolvedEndpoint := renderString(endpoint, sec, decision)
		if err := validateOutboundURL(resolvedEndpoint, def.AllowPrivateURL); err != nil {
			return errorResult(ref.ID, err)
		}
		client := e.Client
		if client == nil {
			client = http.DefaultClient
		}
		timeout := def.Timeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		body, err := renderActionBody(def, sec, decision)
		if err != nil {
			return errorResult(ref.ID, err)
		}
		method := firstNonEmpty(def.Request.Method, def.Method)
		if method == "" {
			method = http.MethodPost
		}
		attempts := def.Retry.Attempts
		if attempts <= 0 {
			attempts = 1
		}
		var resp *http.Response
		for attempt := 1; attempt <= attempts; attempt++ {
			req, reqErr := http.NewRequestWithContext(callCtx, method, resolvedEndpoint, bytes.NewReader(body))
			if reqErr != nil {
				return errorResult(ref.ID, reqErr)
			}
			req.Header.Set("Content-Type", "application/json")
			for key, value := range mergeHeaders(def.Headers, def.Request.Headers) {
				req.Header.Set(key, renderString(value, sec, decision))
			}
			if def.Idempotency.Header != "" && def.Idempotency.Key != "" {
				req.Header.Set(def.Idempotency.Header, renderString(def.Idempotency.Key, sec, decision))
			}
			resp, err = client.Do(req)
			if err == nil {
				if !actionStatusAllowed(resp.StatusCode, def.SuccessCodes) {
					err = fmt.Errorf("action endpoint returned status %d", resp.StatusCode)
				}
			}
			if err == nil {
				break
			}
			if attempt < attempts {
				if resp != nil && !shouldRetryStatus(resp.StatusCode, def.RetryOnCodes) {
					break
				}
				wait := retryBackoff(def.Retry.Backoff, attempt)
				if def.Retry.Jitter {
					wait += time.Duration(rand.Int63n(int64(50 * time.Millisecond)))
				}
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return errorResult(ref.ID, ctx.Err())
				case <-timer.C:
				}
			}
		}
		if err != nil {
			return errorResult(ref.ID, err)
		}
		if def.Idempotency.Header != "" && def.Idempotency.Key != "" {
			result.Fields = map[string]any{"status_code": resp.StatusCode, "idempotency_key": renderString(def.Idempotency.Key, sec, decision)}
		} else {
			result.Fields = map[string]any{"status_code": resp.StatusCode}
		}
		_ = resp.Body.Close()
		return result
	default:
		result.Status = "skipped"
		result.Error = "unknown built-in action"
		return result
	}
}

func actionStatusAllowed(status int, allowed []string) bool {
	if len(allowed) == 0 {
		return status >= 200 && status <= 299
	}
	return codeInRanges(status, allowed)
}

func shouldRetryStatus(status int, retry []string) bool {
	if len(retry) == 0 {
		return status == http.StatusTooManyRequests || status >= 500
	}
	return codeInRanges(status, retry)
}

func codeInRanges(status int, defs []string) bool {
	for _, def := range defs {
		def = strings.TrimSpace(def)
		switch def {
		case "2xx":
			if status >= 200 && status <= 299 {
				return true
			}
		case "4xx":
			if status >= 400 && status <= 499 {
				return true
			}
		case "5xx":
			if status >= 500 && status <= 599 {
				return true
			}
		default:
			if strings.Contains(def, "-") {
				parts := strings.SplitN(def, "-", 2)
				if len(parts) == 2 {
					var lo, hi int
					_, _ = fmt.Sscanf(parts[0], "%d", &lo)
					_, _ = fmt.Sscanf(parts[1], "%d", &hi)
					if status >= lo && status <= hi {
						return true
					}
				}
				continue
			}
			var code int
			_, _ = fmt.Sscanf(def, "%d", &code)
			if code == status {
				return true
			}
		}
	}
	return false
}

func retryBackoff(kind string, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	switch kind {
	case "exponential":
		return time.Duration(1<<min(attempt-1, 6)) * 100 * time.Millisecond
	case "none":
		return 0
	default:
		return time.Duration(attempt) * 100 * time.Millisecond
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func durationArg(args []string, fallback time.Duration) time.Duration {
	for _, arg := range args {
		if d, err := time.ParseDuration(arg); err == nil {
			return d
		}
	}
	return fallback
}

func renderActionBody(def ActionDefinition, sec *Context, decision Decision) ([]byte, error) {
	template := firstNonEmpty(def.Request.BodyTemplate, def.BodyTemplate)
	if template != "" {
		return []byte(renderTemplate(template, sec, decision)), nil
	}
	if len(def.Request.Body) > 0 {
		payload := renderStructuredValue(def.Request.Body, sec, decision)
		if m, ok := payload.(map[string]any); ok {
			for key, value := range def.Request.Fields {
				m[key] = renderStructuredValue(value, sec, decision)
			}
			for alias, path := range def.Request.Include {
				if value, ok := lookupDecisionPath(path, sec, decision); ok {
					m[alias] = value
				}
			}
		}
		return json.Marshal(payload)
	}
	payload := map[string]any{
		"request_id": sec.Request.ID,
		"decision":   decision.Effect,
		"severity":   decision.Severity,
		"risk_score": decision.Risk.Score,
		"findings":   findingIDs(decision.Findings),
	}
	for key, value := range def.Request.Fields {
		payload[key] = value
	}
	for alias, path := range def.Request.Include {
		if value, ok := lookupDecisionPath(path, sec, decision); ok {
			payload[alias] = value
		}
	}
	return json.Marshal(payload)
}

func renderStructuredValue(value any, sec *Context, decision Decision) any {
	switch x := value.(type) {
	case Placeholder:
		if v, ok := lookupDecisionPath(string(x), sec, decision); ok {
			return v
		}
		return nil
	case EnvRef:
		args := decodeRefArgs(string(x))
		if len(args) == 0 {
			return ""
		}
		value := os.Getenv(args[0])
		if value == "" && len(args) > 1 {
			return args[1]
		}
		return value
	case ContextRef:
		args := decodeRefArgs(string(x))
		path := ""
		if len(args) > 0 {
			path = args[0]
		}
		if v, ok := lookupDecisionPath(path, sec, decision); ok {
			return v
		}
		if len(args) > 1 {
			return args[1]
		}
		return nil
	case SessionRef:
		args := decodeRefArgs(string(x))
		path := ""
		if len(args) > 0 {
			path = args[0]
		}
		if !strings.HasPrefix(path, "session.") {
			path = "session." + path
		}
		if v, ok := lookupDecisionPath(path, sec, decision); ok {
			return v
		}
		if len(args) > 1 {
			return args[1]
		}
		return nil
	case string:
		if ref, ok := templateOnlyRef(x); ok {
			if v, found := resolveRef(ref, sec, decision); found {
				return v
			}
		}
		return renderString(x, sec, decision)
	case map[string]any:
		out := map[string]any{}
		for key, child := range x {
			out[key] = renderStructuredValue(child, sec, decision)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = renderStructuredValue(child, sec, decision)
		}
		return out
	default:
		return value
	}
}

func renderTemplate(template string, sec *Context, decision Decision) string {
	out := template
	for {
		start := strings.Index(out, "{{")
		if start < 0 {
			return out
		}
		end := strings.Index(out[start+2:], "}}")
		if end < 0 {
			return out
		}
		raw := strings.TrimSpace(out[start+2 : start+2+end])
		replacement := ""
		if value, ok := resolveRef(raw, sec, decision); ok {
			replacement = stringify(value)
		}
		out = out[:start] + replacement + out[start+2+end+2:]
	}
}

func renderString(s string, sec *Context, decision Decision) string {
	if value, ok := resolveRef(strings.TrimSpace(s), sec, decision); ok {
		return stringify(value)
	}
	return renderTemplate(s, sec, decision)
}

func templateOnlyRef(s string) (string, bool) {
	raw := strings.TrimSpace(s)
	if !strings.HasPrefix(raw, "{{") || !strings.HasSuffix(raw, "}}") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{{"), "}}")), true
}

func resolveRef(raw string, sec *Context, decision Decision) (any, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, `\"`, `"`)
	if strings.HasPrefix(raw, "env(") && strings.HasSuffix(raw, ")") {
		args := splitArgs(strings.TrimSuffix(strings.TrimPrefix(raw, "env("), ")"))
		if len(args) == 0 {
			return "", true
		}
		name := strings.Trim(args[0], `"'`)
		value := os.Getenv(name)
		if value == "" && len(args) > 1 {
			return strings.Trim(args[1], `"'`), true
		}
		return value, true
	}
	if strings.HasPrefix(raw, "env.") {
		return os.Getenv(strings.TrimPrefix(raw, "env.")), true
	}
	if strings.HasPrefix(raw, "context(") && strings.HasSuffix(raw, ")") {
		args := splitArgs(strings.TrimSuffix(strings.TrimPrefix(raw, "context("), ")"))
		if len(args) == 0 {
			return nil, true
		}
		path := strings.Trim(args[0], `"'`)
		value, ok := lookupDecisionPath(path, sec, decision)
		if ok {
			return value, true
		}
		if len(args) > 1 {
			return strings.Trim(args[1], `"'`), true
		}
		return nil, true
	}
	if strings.HasPrefix(raw, "context.") {
		return lookupDecisionPath(strings.TrimPrefix(raw, "context."), sec, decision)
	}
	if strings.HasPrefix(raw, "session(") && strings.HasSuffix(raw, ")") {
		args := splitArgs(strings.TrimSuffix(strings.TrimPrefix(raw, "session("), ")"))
		if len(args) == 0 {
			return nil, true
		}
		path := strings.Trim(args[0], `"'`)
		if !strings.HasPrefix(path, "session.") {
			path = "session." + path
		}
		value, ok := lookupDecisionPath(path, sec, decision)
		if ok {
			return value, true
		}
		if len(args) > 1 {
			return strings.Trim(args[1], `"'`), true
		}
		return nil, true
	}
	if strings.HasPrefix(raw, "session.") {
		return lookupDecisionPath(raw, sec, decision)
	}
	return lookupDecisionPath(raw, sec, decision)
}

func lookupDecisionPath(path string, sec *Context, decision Decision) (any, bool) {
	switch path {
	case "risk.score":
		return decision.Risk.Score, true
	case "risk.confidence":
		return decision.Risk.Confidence, true
	case "severity":
		return decision.Severity, true
	case "decision", "decision.effect":
		return decision.Effect, true
	case "findings":
		return findingIDs(decision.Findings), true
	}
	if sec != nil {
		if sec.Facts == nil {
			sec.rebuildFacts()
		}
		if value, ok := sec.Facts.Get(path); ok {
			return value, true
		}
	}
	return nil, false
}

func mergeHeaders(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range a {
		out[key] = value
	}
	for key, value := range b {
		out[key] = value
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []string:
		return strings.Join(x, ",")
	default:
		data, _ := json.Marshal(x)
		return strings.Trim(string(data), `"`)
	}
}
