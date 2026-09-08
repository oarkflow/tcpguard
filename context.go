package tcpguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	oarkip "github.com/oarkflow/ip"
	condition "github.com/oarkflow/tcpguard/internal/ruleexpr"
	"github.com/oarkflow/wuid"
)

type HTTPContextBuilder struct {
	TrustedProxyHeaders bool
	// TrustedProxyCIDRs optionally restricts which immediate peers may supply
	// forwarded-client-IP headers. If empty, TrustedProxyHeaders preserves the
	// historical behavior and relies on the deployment's proxy sanitization.
	TrustedProxyCIDRs     []string
	DisableGeoIP          bool
	AllowedHosts          []string
	AllowedMethods        []string
	RequireHTTPS          bool
	RequireCSRF           bool
	RequireIdempotency    bool
	SecureResponseHeaders bool
	AllowedCORSOrigins    []string
	CORSAllowCredentials  bool
	ContentSecurityPolicy string
	CSRFTokenValidator    func(*http.Request) bool
	MaxHeaderBytes        int64
	MaxHeaderCount        int
	MaxURLBytes           int64
	MaxBodyBytes          int64
	IdentityExtractor     func(*http.Request, *Context)
	BusinessExtractor     func(*http.Request, *Context)
}

var geoIPInitOnce sync.Once
var geoIPInitErr error

func ensureGeoIPReady() error {
	geoIPInitOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				geoIPInitErr = fmt.Errorf("geoip init panic: %v", r)
			}
		}()
		oarkip.Init()
	})
	return geoIPInitErr
}

func (b HTTPContextBuilder) BuildHTTP(ctx context.Context, r *http.Request) (*Context, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = wuid.NewString()
	}
	ip := remoteIP(r.RemoteAddr)
	if b.TrustedProxyHeaders && trustedProxyPeer(ip, b.TrustedProxyCIDRs) {
		if detected := oarkip.FromHeader(ip, r.Header.Get); detected != "" {
			ip = detected
		}
	}
	network := NetworkContext{IP: ip}
	if !b.DisableGeoIP {
		enrichNetworkGeoIP(&network)
	}
	headers := map[string]string{}
	for key, values := range r.Header {
		headers[key] = strings.Join(values, ",")
	}
	query := map[string]string{}
	for key, values := range r.URL.Query() {
		query[key] = strings.Join(values, ",")
	}
	now := time.Now().UTC()
	sec := &Context{
		Request: RequestContext{
			ID:          id,
			Path:        r.URL.Path,
			Method:      r.Method,
			Headers:     headers,
			Query:       query,
			BodySize:    r.ContentLength,
			ContentType: r.Header.Get("Content-Type"),
			Protocol:    r.Proto,
			Host:        r.Host,
			UserAgent:   r.UserAgent(),
			Origin:      r.Header.Get("Origin"),
			Referer:     r.Header.Get("Referer"),
			HeaderBytes: headerBytes(r.Header),
			HeaderCount: len(r.Header),
			URLBytes:    int64(len(r.URL.RequestURI())),
			EscapedPath: r.URL.EscapedPath(),
			TLS:         r.TLS != nil,
		},
		Network:  network,
		Runtime:  RuntimeContext{Timestamp: now, BusinessHours: isBusinessHour(now)},
		Security: map[string]any{},
		Rate:     map[string]any{},
		Extra:    condition.MapFacts{},
		Raw:      r,
	}
	if hasForwardedHTTPHeaders(r.Header) && (!b.TrustedProxyHeaders || !trustedProxyPeer(ip, b.TrustedProxyCIDRs)) {
		setContextFact(sec, "security.forwarded_headers_untrusted", true)
	}
	if b.RequireHTTPS && r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		setContextFact(sec, "security.https_required", true)
	}
	if b.RequireCSRF && csrfRequired(r) && csrfMissing(r) {
		setContextFact(sec, "security.csrf_missing", true)
	}
	if b.RequireCSRF && csrfRequired(r) && b.CSRFTokenValidator != nil && !b.CSRFTokenValidator(r) {
		setContextFact(sec, "security.csrf_missing", true)
	}
	if r.Header.Get("Origin") != "" && len(b.AllowedCORSOrigins) > 0 && !corsOriginAllowed(r.Header.Get("Origin"), b.AllowedCORSOrigins) {
		setContextFact(sec, "security.cors_origin_not_allowed", true)
	}
	if b.RequireIdempotency && idempotencyRequired(r) && strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		setContextFact(sec, "security.idempotency_missing", true)
	}
	if len(b.AllowedHosts) > 0 && !hostAllowed(r.Host, b.AllowedHosts) {
		setContextFact(sec, "security.host_not_allowed", true)
	}
	if len(b.AllowedMethods) > 0 && !stringInFold(r.Method, b.AllowedMethods) {
		setContextFact(sec, "security.method_not_allowed", true)
	}
	if b.MaxHeaderBytes > 0 && sec.Request.HeaderBytes > b.MaxHeaderBytes {
		setContextFact(sec, "security.headers_oversized", true)
	}
	if b.MaxHeaderCount > 0 && sec.Request.HeaderCount > b.MaxHeaderCount {
		setContextFact(sec, "security.header_count_exceeded", true)
	}
	if b.MaxURLBytes > 0 && sec.Request.URLBytes > b.MaxURLBytes {
		setContextFact(sec, "security.url_oversized", true)
	}
	if b.MaxBodyBytes > 0 && r.ContentLength > b.MaxBodyBytes {
		setContextFact(sec, "security.body_oversized", true)
	}
	sec.Runtime.Holiday = false
	sec.Business.OutsideHours = !sec.Runtime.BusinessHours
	if b.IdentityExtractor != nil {
		b.IdentityExtractor(r, sec)
	}
	if b.BusinessExtractor != nil {
		b.BusinessExtractor(r, sec)
	}
	sec.rebuildFacts()
	return sec, nil
}

func headerBytes(headers http.Header) int64 {
	var n int64
	for key, values := range headers {
		n += int64(len(key))
		for _, value := range values {
			n += int64(len(value))
		}
	}
	return n
}

func hasForwardedHTTPHeaders(headers http.Header) bool {
	for key := range headers {
		switch strings.ToLower(key) {
		case "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "x-original-url", "x-rewrite-url":
			return true
		}
	}
	return false
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, candidate := range allowed {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == host || (strings.HasPrefix(candidate, "*.") && strings.HasSuffix(host, candidate[1:])) {
			return true
		}
	}
	return false
}

func stringInFold(value string, values []string) bool {
	for _, candidate := range values {
		if strings.EqualFold(value, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func csrfRequired(r *http.Request) bool {
	return r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete
}

func csrfMissing(r *http.Request) bool {
	if r.Header.Get("Cookie") == "" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	return origin != "" && !sameOrigin(origin, r.Host) && strings.TrimSpace(r.Header.Get("X-CSRF-Token")) == ""
}

func idempotencyRequired(r *http.Request) bool {
	return r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete
}

func corsOriginAllowed(origin string, allowed []string) bool {
	origin = strings.TrimRight(strings.ToLower(strings.TrimSpace(origin)), "/")
	if origin == "" {
		return false
	}
	for _, candidate := range allowed {
		candidate = strings.TrimRight(strings.ToLower(strings.TrimSpace(candidate)), "/")
		if candidate == origin || candidate == "*" {
			return true
		}
	}
	return false
}

func trustedProxyPeer(remote string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	peer := net.ParseIP(remote)
	if peer == nil {
		return false
	}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && network.Contains(peer) {
			return true
		}
	}
	return false
}

func enrichNetworkGeoIP(network *NetworkContext) {
	if network == nil || network.IP == "" {
		return
	}
	if err := ensureGeoIPReady(); err != nil {
		return
	}
	record := oarkip.Lookup(network.IP)
	if !record.Found {
		return
	}
	network.GeoFound = true
	countryCode := oarkip.Country(network.IP)
	if countryCode == "" {
		countryCode = record.Country
	}
	if countryCode == "" {
		countryCode = record.CountryCode
	}
	network.CountryCode = countryCode
	if network.Country == "" {
		network.Country = countryCode
	}
	if record.Country != "" && record.Country != countryCode {
		network.CountryName = record.Country
	}
	network.Region = record.Region
	network.City = record.City
	network.Latitude = record.Latitude
	network.Longitude = record.Longitude
}

func (c *Context) rebuildFacts() {
	facts := condition.MapFacts{
		"request": map[string]any{
			"id":           c.Request.ID,
			"path":         c.Request.Path,
			"method":       c.Request.Method,
			"headers":      c.Request.Headers,
			"query":        c.Request.Query,
			"body_size":    c.Request.BodySize,
			"content_type": c.Request.ContentType,
			"protocol":     c.Request.Protocol,
			"host":         c.Request.Host,
			"user_agent":   c.Request.UserAgent,
			"origin":       c.Request.Origin,
			"referer":      c.Request.Referer,
			"params":       c.Request.Params,
			"header_bytes": c.Request.HeaderBytes,
			"header_count": c.Request.HeaderCount,
			"url_bytes":    c.Request.URLBytes,
			"escaped_path": c.Request.EscapedPath,
			"tls":          c.Request.TLS,
		},
		"network": map[string]any{
			"ip":               c.Network.IP,
			"country_code":     c.Network.CountryCode,
			"country":          c.Network.Country,
			"country_name":     c.Network.CountryName,
			"region":           c.Network.Region,
			"city":             c.Network.City,
			"latitude":         c.Network.Latitude,
			"longitude":        c.Network.Longitude,
			"geo_found":        c.Network.GeoFound,
			"asn":              c.Network.ASN,
			"proxy":            c.Network.Proxy,
			"vpn":              c.Network.VPN,
			"tor":              c.Network.Tor,
			"reputation":       c.Network.Reputation,
			"intel_source":     c.Network.IntelSource,
			"intel_match_type": c.Network.IntelMatchType,
			"intel_confidence": c.Network.IntelConfidence,
			"previous_ip":      c.Network.PreviousIP,
			"previous_country": c.Network.PreviousCountry,
		},
		"user": map[string]any{
			"id":          c.Identity.ID,
			"role":        c.Identity.Role,
			"roles":       c.Identity.Roles,
			"tenant":      c.Identity.Tenant,
			"permissions": c.Identity.Permissions,
			"auth_method": c.Identity.AuthMethod,
		},
		"tenant": map[string]any{
			"id":          c.Tenant.ID,
			"plan":        c.Tenant.Plan,
			"environment": c.Tenant.Environment,
			"metadata":    c.Tenant.Metadata,
		},
		"session": map[string]any{
			"id":                 c.Session.ID,
			"device_id":          c.Session.DeviceID,
			"user_agent":         c.Session.UserAgent,
			"fingerprint":        c.Session.Fingerprint,
			"previous_ip":        c.Session.PreviousIP,
			"previous_country":   c.Session.PreviousCountry,
			"last_seen_age":      c.Session.LastSeenAge,
			"device":             map[string]any{"id": c.Session.DeviceID, "new": c.Session.NewDevice, "is_new": c.Session.NewDevice},
			"country_changed":    c.Session.CountryChanged,
			"asn_changed":        c.Session.ASNChanged,
			"device_changed":     c.Session.DeviceChanged,
			"user_agent_changed": c.Session.UserAgentChanged,
		},
		"device": map[string]any{
			"id":          c.Device.ID,
			"fingerprint": c.Device.Fingerprint,
			"new":         c.Device.New,
			"is_new":      c.Device.New,
			"user_agent":  c.Device.UserAgent,
		},
		"business": map[string]any{
			"action":         c.Business.Action,
			"entity":         c.Business.Entity,
			"amount":         c.Business.Amount,
			"workflow":       c.Business.Workflow,
			"approval_level": c.Business.ApprovalLevel,
			"sensitivity":    c.Business.Sensitivity,
			"outside_hours":  c.Business.OutsideHours,
			"holiday":        c.Business.Holiday,
		},
		"runtime": map[string]any{
			"timestamp":      c.Runtime.Timestamp.Format(time.RFC3339Nano),
			"business_hours": c.Runtime.BusinessHours,
			"holiday":        c.Runtime.Holiday,
			"policy_version": c.Runtime.PolicyVersion,
			"config_hash":    c.Runtime.ConfigHash,
		},
		"security": c.Security,
		"rate":     c.Rate,
	}
	mergeFacts(facts, c.Extra)
	c.Facts = facts
}

func setFact(root condition.MapFacts, path string, value any) {
	cur := map[string]any(root)
	for {
		dot := strings.IndexByte(path, '.')
		if dot < 0 {
			if path != "" {
				cur[path] = value
			}
			return
		}
		part := path[:dot]
		if part == "" {
			path = path[dot+1:]
			continue
		}
		path = path[dot+1:]
		if path == "" {
			cur[part] = value
			return
		}
		next, _ := cur[part].(map[string]any)
		if next == nil {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
}

func mergeFacts(dst, src condition.MapFacts) {
	for key, value := range src {
		if srcMap, ok := asAnyMap(value); ok {
			if dstMap, ok := asAnyMap(dst[key]); ok {
				mergeFacts(condition.MapFacts(dstMap), condition.MapFacts(srcMap))
				continue
			}
		}
		dst[key] = value
	}
}

func asAnyMap(v any) (map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		return x, true
	case condition.MapFacts:
		return map[string]any(x), true
	default:
		return nil, false
	}
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}

func isBusinessHour(t time.Time) bool {
	weekday := t.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return false
	}
	hour := t.Hour()
	return hour >= 9 && hour < 17
}
