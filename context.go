package tcpguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/condition"
	oarkip "github.com/oarkflow/ip"
)

type HTTPContextBuilder struct {
	TrustedProxyHeaders bool
	DisableGeoIP        bool
	IdentityExtractor   func(*http.Request, *Context)
	BusinessExtractor   func(*http.Request, *Context)
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
		id = uuid.NewString()
	}
	ip := remoteIP(r.RemoteAddr)
	if b.TrustedProxyHeaders {
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
		},
		Network:  network,
		Runtime:  RuntimeContext{Timestamp: now, BusinessHours: isBusinessHour(now)},
		Security: map[string]any{},
		Rate:     map[string]any{},
		Extra:    condition.MapFacts{},
		Raw:      r,
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
	parts := strings.Split(path, ".")
	cur := map[string]any(root)
	for i, part := range parts {
		if i == len(parts)-1 {
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

func firstCSV(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func isBusinessHour(t time.Time) bool {
	weekday := t.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return false
	}
	hour := t.Hour()
	return hour >= 9 && hour < 17
}
