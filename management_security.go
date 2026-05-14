package tcpguard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ManagementRoute string

const (
	ManagementRouteHealth           ManagementRoute = "health"
	ManagementRouteReload           ManagementRoute = "reload"
	ManagementRouteSimulate         ManagementRoute = "simulate"
	ManagementRouteExplain          ManagementRoute = "explain"
	ManagementRouteIncidents        ManagementRoute = "incidents"
	ManagementRouteAudit            ManagementRoute = "audit"
	ManagementRouteAuditVerify      ManagementRoute = "audit_verify"
	ManagementRouteApprovals        ManagementRoute = "approvals"
	ManagementRouteApprovalsApprove ManagementRoute = "approvals_approve"
	ManagementRouteApprovalsReject  ManagementRoute = "approvals_reject"
)

type ManagementPrincipal struct {
	Subject string
	Roles   []string
}

type ManagementAuthProvider interface {
	Authenticate(*http.Request) (ManagementPrincipal, error)
}

type ManagementAuthorizer interface {
	Authorize(route ManagementRoute, principal ManagementPrincipal) bool
}

type ManagementServerConfig struct {
	AuthProvider      ManagementAuthProvider
	Authorizer        ManagementAuthorizer
	MaxBodyBytes      int64
	ReadTimeout       time.Duration
	PerIPRateLimit    int
	RateLimitWindow   time.Duration
	AllowedCIDRs      []string
	AllowHealthNoAuth bool
}

type StaticAPIKeyAuth struct {
	Header string
	Keys   map[string]ManagementPrincipal
}

func (a StaticAPIKeyAuth) Authenticate(r *http.Request) (ManagementPrincipal, error) {
	header := a.Header
	if header == "" {
		header = "X-API-Key"
	}
	key := strings.TrimSpace(r.Header.Get(header))
	if key == "" {
		return ManagementPrincipal{}, errors.New("missing api key")
	}
	p, ok := a.Keys[key]
	if !ok {
		return ManagementPrincipal{}, errors.New("invalid api key")
	}
	if p.Subject == "" {
		p.Subject = "api-key"
	}
	return p, nil
}

type MTLSAuth struct {
	RequireVerified bool
	AllowedSubjects map[string]bool
}

func (a MTLSAuth) Authenticate(r *http.Request) (ManagementPrincipal, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ManagementPrincipal{}, errors.New("missing client certificate")
	}
	if a.RequireVerified && len(r.TLS.VerifiedChains) == 0 {
		return ManagementPrincipal{}, errors.New("client certificate not verified")
	}
	subj := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.String())
	if len(a.AllowedSubjects) > 0 && !a.AllowedSubjects[subj] {
		return ManagementPrincipal{}, errors.New("client certificate subject not allowed")
	}
	return ManagementPrincipal{Subject: subj, Roles: []string{"mtls"}}, nil
}

type JWTAuth struct {
	Header string
	Secret []byte
}

func (a JWTAuth) Authenticate(r *http.Request) (ManagementPrincipal, error) {
	header := a.Header
	if header == "" {
		header = "Authorization"
	}
	raw := strings.TrimSpace(r.Header.Get(header))
	if raw == "" {
		return ManagementPrincipal{}, errors.New("missing bearer token")
	}
	token := strings.TrimPrefix(raw, "Bearer ")
	subject, roles, err := parseAndValidateHS256JWT(token, a.Secret)
	if err != nil {
		return ManagementPrincipal{}, err
	}
	return ManagementPrincipal{Subject: subject, Roles: roles}, nil
}

type ChainAuthProvider []ManagementAuthProvider

func (c ChainAuthProvider) Authenticate(r *http.Request) (ManagementPrincipal, error) {
	var errs []string
	for _, provider := range c {
		if provider == nil {
			continue
		}
		p, err := provider.Authenticate(r)
		if err == nil {
			return p, nil
		}
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return ManagementPrincipal{}, errors.New("no auth provider configured")
	}
	return ManagementPrincipal{}, fmt.Errorf("authentication failed: %s", strings.Join(errs, "; "))
}

type RoleBasedAuthorizer struct {
	RolesByRoute map[ManagementRoute][]string
}

func (a RoleBasedAuthorizer) Authorize(route ManagementRoute, principal ManagementPrincipal) bool {
	required := a.RolesByRoute[route]
	if len(required) == 0 {
		return false
	}
	for _, role := range required {
		for _, got := range principal.Roles {
			if role == got {
				return true
			}
		}
	}
	return false
}

type rateWindow struct {
	count   int
	started time.Time
}

var mgmtRate sync.Map

func enforceManagementRateLimit(cfg ManagementServerConfig, key string) bool {
	if cfg.PerIPRateLimit <= 0 {
		return true
	}
	window := cfg.RateLimitWindow
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now()
	raw, _ := mgmtRate.LoadOrStore(key, &rateWindow{started: now})
	state, _ := raw.(*rateWindow)
	if state == nil {
		return true
	}
	if now.Sub(state.started) > window {
		state.started = now
		state.count = 0
	}
	state.count++
	return state.count <= cfg.PerIPRateLimit
}

func managementRouteOf(r *http.Request) (ManagementRoute, bool) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		return ManagementRouteHealth, true
	case r.Method == http.MethodPost && r.URL.Path == "/reload":
		return ManagementRouteReload, true
	case r.Method == http.MethodPost && r.URL.Path == "/simulate":
		return ManagementRouteSimulate, true
	case r.Method == http.MethodPost && r.URL.Path == "/explain":
		return ManagementRouteExplain, true
	case r.Method == http.MethodGet && r.URL.Path == "/incidents":
		return ManagementRouteIncidents, true
	case r.Method == http.MethodGet && r.URL.Path == "/audit":
		return ManagementRouteAudit, true
	case r.Method == http.MethodGet && r.URL.Path == "/audit/verify":
		return ManagementRouteAuditVerify, true
	case r.Method == http.MethodGet && r.URL.Path == "/approvals":
		return ManagementRouteApprovals, true
	case r.Method == http.MethodPost && r.URL.Path == "/approvals/approve":
		return ManagementRouteApprovalsApprove, true
	case r.Method == http.MethodPost && r.URL.Path == "/approvals/reject":
		return ManagementRouteApprovalsReject, true
	default:
		return "", false
	}
}

func managementRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func ipAllowed(ip string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}

func parseAndValidateHS256JWT(token string, secret []byte) (string, []string, error) {
	if len(secret) == 0 {
		return "", nil, errors.New("jwt secret is not configured")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, errors.New("invalid jwt format")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, expected) {
		return "", nil, errors.New("invalid jwt signature")
	}
	var payload struct {
		Sub   string   `json:"sub"`
		Roles []string `json:"roles"`
		Exp   int64    `json:"exp"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, errors.New("invalid jwt payload")
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", nil, errors.New("invalid jwt payload json")
	}
	if payload.Exp > 0 && time.Now().Unix() > payload.Exp {
		return "", nil, errors.New("jwt is expired")
	}
	if payload.Sub == "" {
		return "", nil, errors.New("jwt subject is required")
	}
	return payload.Sub, payload.Roles, nil
}

func NewManagementServer(guard *ReloadableGuard, cfg ManagementServerConfig) ManagementServer {
	return ManagementServer{Guard: guard, Config: cfg}
}

func (s ManagementServer) authorizeManagementRequest(w http.ResponseWriter, r *http.Request) (ManagementRoute, bool) {
	route, known := managementRouteOf(r)
	if !known {
		writeManagementError(w, http.StatusNotFound, "not found")
		return "", false
	}
	if route == ManagementRouteHealth && s.Config.AllowHealthNoAuth {
		return route, true
	}
	ip := managementRemoteIP(r)
	if !ipAllowed(ip, s.Config.AllowedCIDRs) {
		writeManagementError(w, http.StatusForbidden, "source ip is not allowed")
		return "", false
	}
	if !enforceManagementRateLimit(s.Config, ip+"|"+string(route)) {
		writeManagementError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return "", false
	}
	if s.Config.AuthProvider == nil {
		writeManagementError(w, http.StatusUnauthorized, "management auth provider is required")
		return "", false
	}
	principal, err := s.Config.AuthProvider.Authenticate(r)
	if err != nil {
		writeManagementError(w, http.StatusUnauthorized, err.Error())
		return "", false
	}
	if s.Config.Authorizer == nil || !s.Config.Authorizer.Authorize(route, principal) {
		writeManagementError(w, http.StatusForbidden, "forbidden")
		return "", false
	}
	return route, true
}

func managementContext(r *http.Request, cfg ManagementServerConfig) (context.Context, context.CancelFunc) {
	if cfg.ReadTimeout <= 0 {
		return r.Context(), func() {}
	}
	return context.WithTimeout(r.Context(), cfg.ReadTimeout)
}
