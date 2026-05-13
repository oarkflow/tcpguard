package tcpguard

import (
	"net"
	"path"
	"strings"

	"github.com/gofiber/fiber/v3"
)

type RequestMatcher struct {
	Name           string              `json:"name,omitempty"`
	All            []RequestMatcher    `json:"all,omitempty"`
	Any            []RequestMatcher    `json:"any,omitempty"`
	Not            []RequestMatcher    `json:"not,omitempty"`
	Methods        []string            `json:"methods,omitempty"`
	Paths          []string            `json:"paths,omitempty"`
	PathPrefixes   []string            `json:"pathPrefixes,omitempty"`
	FileExtensions []string            `json:"fileExtensions,omitempty"`
	HeaderKeys     []string            `json:"headerKeys,omitempty"`
	Headers        map[string][]string `json:"headers,omitempty"`
	CookieKeys     []string            `json:"cookieKeys,omitempty"`
	Cookies        map[string][]string `json:"cookies,omitempty"`
	QueryKeys      []string            `json:"queryKeys,omitempty"`
	Query          map[string][]string `json:"query,omitempty"`
	UserAgents     []string            `json:"userAgents,omitempty"`
	ContentTypes   []string            `json:"contentTypes,omitempty"`
	Accepts        []string            `json:"accepts,omitempty"`
	ClientCIDRs    []string            `json:"clientCIDRs,omitempty"`
	Users          []string            `json:"users,omitempty"`
	Groups         []string            `json:"groups,omitempty"`
}

func requestMatchesAny(c fiber.Ctx, userID string, userGroups []string, matchers []RequestMatcher) bool {
	for _, matcher := range matchers {
		if requestMatches(c, userID, userGroups, matcher) {
			return true
		}
	}
	return false
}

func requestMatches(c fiber.Ctx, userID string, userGroups []string, matcher RequestMatcher) bool {
	for _, child := range matcher.Not {
		if requestMatches(c, userID, userGroups, child) {
			return false
		}
	}
	for _, child := range matcher.All {
		if !requestMatches(c, userID, userGroups, child) {
			return false
		}
	}
	if len(matcher.Any) > 0 {
		any := false
		for _, child := range matcher.Any {
			if requestMatches(c, userID, userGroups, child) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}

	pathValue := c.Path()
	if len(matcher.Methods) > 0 && !containsStringIgnoreCase(matcher.Methods, c.Method()) {
		return false
	}
	if len(matcher.Paths) > 0 && !matchesAnyPathPattern(pathValue, matcher.Paths) {
		return false
	}
	if len(matcher.PathPrefixes) > 0 && !hasAnyPrefix(pathValue, matcher.PathPrefixes) {
		return false
	}
	if len(matcher.FileExtensions) > 0 && !hasAnyFileExtension(pathValue, matcher.FileExtensions) {
		return false
	}
	if len(matcher.HeaderKeys) > 0 && !hasAllHeaders(c, matcher.HeaderKeys) {
		return false
	}
	if len(matcher.Headers) > 0 && !headersMatch(c, matcher.Headers) {
		return false
	}
	if len(matcher.CookieKeys) > 0 && !hasAllMapKeys(injectionParseCookieHeader(c.Get(fiber.HeaderCookie)), matcher.CookieKeys) {
		return false
	}
	if len(matcher.Cookies) > 0 && !valuesMatch(injectionParseCookieHeader(c.Get(fiber.HeaderCookie)), matcher.Cookies) {
		return false
	}
	if len(matcher.QueryKeys) > 0 && !hasAllMapKeys(c.Queries(), matcher.QueryKeys) {
		return false
	}
	if len(matcher.Query) > 0 && !valuesMatch(c.Queries(), matcher.Query) {
		return false
	}
	if len(matcher.UserAgents) > 0 && !matchesAnyValue(c.Get(fiber.HeaderUserAgent), matcher.UserAgents) {
		return false
	}
	if len(matcher.ContentTypes) > 0 && !matchesAnyValue(c.Get(fiber.HeaderContentType), matcher.ContentTypes) {
		return false
	}
	if len(matcher.Accepts) > 0 && !matchesAnyValue(c.Get(fiber.HeaderAccept), matcher.Accepts) {
		return false
	}
	if len(matcher.ClientCIDRs) > 0 && !clientMatchesAnyCIDR(c, matcher.ClientCIDRs) {
		return false
	}
	if len(matcher.Users) > 0 && !containsStringIgnoreCase(matcher.Users, userID) {
		return false
	}
	if len(matcher.Groups) > 0 && !intersectsIgnoreCase(matcher.Groups, userGroups) {
		return false
	}
	return true
}

func matchesAnyPathPattern(pathValue string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPathPattern(pathValue, pattern) || globMatch(pattern, pathValue) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix = strings.TrimSpace(prefix); prefix != "" && strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func hasAnyFileExtension(pathValue string, extensions []string) bool {
	pathValue = strings.ToLower(pathValue)
	for _, ext := range extensions {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		if strings.HasSuffix(pathValue, ext) {
			return true
		}
	}
	return false
}

func hasAllHeaders(c fiber.Ctx, keys []string) bool {
	for _, key := range keys {
		if strings.TrimSpace(c.Get(key)) == "" {
			return false
		}
	}
	return true
}

func headersMatch(c fiber.Ctx, expected map[string][]string) bool {
	for key, patterns := range expected {
		if !matchesAnyValue(c.Get(key), patterns) {
			return false
		}
	}
	return true
}

func hasAllMapKeys(values map[string]string, keys []string) bool {
	for _, key := range keys {
		if _, ok := lookupMapValue(values, key); !ok {
			return false
		}
	}
	return true
}

func valuesMatch(values map[string]string, expected map[string][]string) bool {
	for key, patterns := range expected {
		value, ok := lookupMapValue(values, key)
		if !ok || !matchesAnyValue(value, patterns) {
			return false
		}
	}
	return true
}

func lookupMapValue(values map[string]string, key string) (string, bool) {
	if value, ok := values[key]; ok {
		return value, true
	}
	for gotKey, value := range values {
		if strings.EqualFold(gotKey, key) {
			return value, true
		}
	}
	return "", false
}

func matchesAnyValue(value string, patterns []string) bool {
	if len(patterns) == 0 {
		return strings.TrimSpace(value) != ""
	}
	for _, pattern := range patterns {
		if valueMatchesPattern(value, pattern) {
			return true
		}
	}
	return false
}

func valueMatchesPattern(value, patternValue string) bool {
	patternValue = strings.TrimSpace(patternValue)
	if patternValue == "" {
		return value == ""
	}
	if patternValue == "*" {
		return strings.TrimSpace(value) != ""
	}
	if globMatch(patternValue, value) {
		return true
	}
	return strings.EqualFold(value, patternValue)
}

func globMatch(patternValue, value string) bool {
	ok, err := path.Match(patternValue, value)
	if err == nil && ok {
		return true
	}
	lowerPattern := strings.ToLower(patternValue)
	lowerValue := strings.ToLower(value)
	ok, err = path.Match(lowerPattern, lowerValue)
	if err == nil && ok {
		return true
	}
	if strings.HasPrefix(lowerPattern, "*") && strings.HasSuffix(lowerPattern, "*") {
		return strings.Contains(lowerValue, strings.Trim(lowerPattern, "*"))
	}
	if strings.HasPrefix(lowerPattern, "*") {
		return strings.HasSuffix(lowerValue, strings.TrimPrefix(lowerPattern, "*"))
	}
	if strings.HasSuffix(lowerPattern, "*") {
		return strings.HasPrefix(lowerValue, strings.TrimSuffix(lowerPattern, "*"))
	}
	return false
}

func clientMatchesAnyCIDR(c fiber.Ctx, cidrs []string) bool {
	clientIP := c.RequestCtx().RemoteIP()
	if clientIP == nil {
		return false
	}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if ip := net.ParseIP(cidr); ip != nil && ip.Equal(clientIP) {
			return true
		}
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(clientIP) {
			return true
		}
	}
	return false
}

func intersectsIgnoreCase(left, right []string) bool {
	for _, l := range left {
		if containsStringIgnoreCase(right, l) {
			return true
		}
	}
	return false
}
