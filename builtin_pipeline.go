package tcpguard

import (
	"strconv"
	"strings"
	"time"
)

func registerDefaultPipelineFunctions(reg PipelineFunctionRegistry) {
	if reg == nil {
		return
	}
	register := func(name string, fn func(ctx *Context) any) {
		if name == "" || fn == nil {
			return
		}
		if _, exists := reg.Get(name); exists {
			return
		}
		reg.Register(name, fn)
	}

	register("checkEndpoint", pipelineCheckEndpoint)
	register("getCurrentTime", pipelineGetCurrentTime)
	register("parseTime", pipelineParseTime)
	register("checkBusinessHours", pipelineCheckBusinessHours)
	register("getClientIP", pipelineGetClientIP)
	register("getCountryFromIP", pipelineGetCountryFromIP)
	register("checkBusinessRegion", pipelineCheckBusinessRegion)
	register("checkProtectedRoute", pipelineCheckProtectedRoute)
	register("checkSessionHijacking", pipelineCheckSessionHijacking)
	register("ddos", AdvancedDDoSCondition)
	register("mitm", AdvancedMITMCondition)
}

func pipelineCheckEndpoint(ctx *Context) any {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}
	expected, _ := ctx.Results["endpoint"].(string)
	if expected == "" {
		return true
	}
	path := ctx.FiberCtx.Path()
	matchType, _ := ctx.Results["matchType"].(string)
	switch strings.ToLower(matchType) {
	case "prefix":
		return strings.HasPrefix(path, expected)
	case "suffix":
		return strings.HasSuffix(path, expected)
	case "contains":
		return strings.Contains(path, expected)
	default:
		return path == expected
	}
}

func pipelineGetCurrentTime(ctx *Context) any {
	return time.Now()
}

func pipelineParseTime(ctx *Context) any {
	timeStr, _ := ctx.Results["timeString"].(string)
	if timeStr == "" {
		return time.Time{}
	}
	layout, _ := ctx.Results["layout"].(string)
	if layout == "" {
		layout = "15:04"
	}
	timezone, _ := ctx.Results["timezone"].(string)
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	parsed, err := time.ParseInLocation(layout, timeStr, loc)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func pipelineCheckBusinessHours(ctx *Context) any {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}
	endpoint, _ := ctx.Results["endpoint"].(string)
	if endpoint != "" && ctx.FiberCtx.Path() != endpoint {
		if !strings.HasPrefix(ctx.FiberCtx.Path(), endpoint) {
			return false
		}
	}
	timezone, _ := ctx.Results["timezone"].(string)
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	if current, ok := ctx.Results["get_time"].(time.Time); ok && !current.IsZero() {
		now = current.In(loc)
	}
	start := extractTimeFromContext(ctx, []string{"parse_start", "startTime", "start"}, loc)
	end := extractTimeFromContext(ctx, []string{"parse_end", "endTime", "end"}, loc)
	if start.IsZero() || end.IsZero() {
		return false
	}
	start = time.Date(now.Year(), now.Month(), now.Day(), start.Hour(), start.Minute(), 0, 0, loc)
	end = time.Date(now.Year(), now.Month(), now.Day(), end.Hour(), end.Minute(), 0, 0, loc)
	if start.After(end) {
		end = end.Add(24 * time.Hour)
	}
	if allowed := toStringSlice(ctx.Results["allowedDays"]); len(allowed) > 0 {
		if !containsStringIgnoreCase(allowed, now.Weekday().String()) {
			return true
		}
	}
	if denied := toStringSlice(ctx.Results["blockedDays"]); len(denied) > 0 {
		if containsStringIgnoreCase(denied, now.Weekday().String()) {
			return true
		}
	}
	outside := now.Before(start) || now.After(end)
	blockInside, _ := ctx.Results["blockInsideWindow"].(bool)
	if blockInside {
		return !outside
	}
	return outside
}

func pipelineGetClientIP(ctx *Context) any {
	if ctx == nil || ctx.RuleEngine == nil || ctx.FiberCtx == nil {
		return ""
	}
	return ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
}

func pipelineGetCountryFromIP(ctx *Context) any {
	if ctx == nil || ctx.FiberCtx == nil {
		return ""
	}
	ipAddr, _ := ctx.Results["get_ip"].(string)
	if ipAddr == "" {
		ipAddr = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}
	defaultCountry, _ := ctx.Results["defaultCountry"].(string)
	if defaultCountry == "" {
		defaultCountry = "US"
	}
	if ctx.RuleEngine == nil {
		return defaultCountry
	}
	return ctx.RuleEngine.GetCountryFromIP(ipAddr, defaultCountry)
}

func pipelineCheckBusinessRegion(ctx *Context) any {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}
	endpoint, _ := ctx.Results["endpoint"].(string)
	if endpoint != "" && ctx.FiberCtx.Path() != endpoint {
		if !strings.HasPrefix(ctx.FiberCtx.Path(), endpoint) {
			return false
		}
	}
	country := ""
	if val, ok := ctx.Results["get_country"].(string); ok {
		country = val
	}
	if country == "" {
		if val, ok := ctx.Results["country"].(string); ok {
			country = val
		}
	}
	allowed := toStringSlice(ctx.Results["allowedCountries"])
	denied := toStringSlice(ctx.Results["deniedCountries"])
	if len(denied) > 0 && containsStringIgnoreCase(denied, country) {
		return true
	}
	if len(allowed) == 0 {
		return false
	}
	return !containsStringIgnoreCase(allowed, country)
}

func pipelineCheckProtectedRoute(ctx *Context) any {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}
	routes := toStringSlice(ctx.Results["protectedRoutes"])
	if len(routes) == 0 {
		return false
	}
	path := ctx.FiberCtx.Path()
	matched := false
	for _, route := range routes {
		if route == "" {
			continue
		}
		if strings.HasSuffix(route, "*") {
			prefix := strings.TrimSuffix(route, "*")
			if strings.HasPrefix(path, prefix) {
				matched = true
				break
			}
		} else if path == route || strings.HasPrefix(path, route) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	header := "Authorization"
	if custom, ok := ctx.Results["loginCheckHeader"].(string); ok && custom != "" {
		header = custom
	}
	headerValue := ctx.FiberCtx.Get(header)
	if required := toStringSlice(ctx.Results["requiredHeaderValues"]); len(required) > 0 {
		for _, val := range required {
			if headerValue == val {
				return false
			}
		}
		return true
	}
	return headerValue == ""
}

func pipelineCheckSessionHijacking(ctx *Context) any {
	if ctx == nil || ctx.RuleEngine == nil || ctx.RuleEngine.Store == nil || ctx.FiberCtx == nil {
		return false
	}
	userID := ctx.RuleEngine.GetUserID(ctx.FiberCtx)
	if userID == "" {
		return false
	}
	sessions, err := ctx.RuleEngine.Store.GetSessions(userID)
	if err != nil {
		return false
	}
	if sessions == nil {
		sessions = []*SessionInfo{}
	}
	now := time.Now()
	timeout := parseDurationOrDefault(ctx.Results["sessionTimeout"], 24*time.Hour)
	maxConcurrent := int(readFloatOrDefault(ctx.Results["maxConcurrentSessions"], 1))
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	var valid []*SessionInfo
	for _, s := range sessions {
		if now.Sub(s.Created) < timeout {
			valid = append(valid, s)
		}
	}
	userAgent := ctx.FiberCtx.Get("User-Agent")
	clientIP := ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	sameFingerprint := func(s *SessionInfo) bool {
		if s == nil {
			return false
		}
		if s.UA != "" && s.UA == userAgent {
			if s.IP == "" || s.IP == clientIP {
				return true
			}
		}
		return false
	}
	for _, s := range valid {
		if sameFingerprint(s) {
			s.LastSeen = now
			ctx.RuleEngine.Store.PutSessions(userID, valid)
			return false
		}
	}
	suspicious := false
	for _, s := range valid {
		if s.UA == userAgent && clientIP != "" && s.IP != "" && s.IP != clientIP {
			suspicious = true
			break
		}
	}
	if !suspicious {
		if len(valid) >= maxConcurrent {
			suspicious = true
		} else {
			valid = append(valid, &SessionInfo{
				UA:       userAgent,
				IP:       clientIP,
				Created:  now,
				LastSeen: now,
			})
		}
	}
	ctx.RuleEngine.Store.PutSessions(userID, valid)
	return suspicious
}

func extractTimeFromContext(ctx *Context, keys []string, loc *time.Location) time.Time {
	for _, key := range keys {
		if v, ok := ctx.Results[key].(time.Time); ok {
			return v.In(loc)
		}
		if str, ok := ctx.Results[key].(string); ok && str != "" {
			if parsed, err := time.ParseInLocation("15:04", str, loc); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

func toStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func containsStringIgnoreCase(list []string, candidate string) bool {
	if candidate == "" {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(item, candidate) {
			return true
		}
	}
	return false
}

func parseDurationOrDefault(input any, fallback time.Duration) time.Duration {
	if str, ok := input.(string); ok && str != "" {
		if d, err := time.ParseDuration(str); err == nil {
			return d
		}
	}
	if f, ok := input.(float64); ok && f > 0 {
		return time.Duration(f)
	}
	return fallback
}

func readFloatOrDefault(value any, fallback float64) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			return parsed
		}
	}
	return fallback
}
