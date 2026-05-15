package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oarkflow/tcpguard"
	"github.com/oarkflow/tcpguard/bcl"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18182", "listen address")
	policy := flag.String("policy", "./examples/tcpguard_http_server/policy", "TCPGuard policy directory")
	flag.Parse()

	ctx := context.Background()
	bundle, err := bcl.LoadTCPGuardBundleDir(ctx, *policy)
	if err != nil {
		log.Fatal(err)
	}

	metrics := tcpguard.NewMemoryMetrics()
	store := tcpguard.NewMemoryStore()
	guard, err := tcpguard.New(
		tcpguard.WithBundle(bundle),
		tcpguard.WithStore(store),
		tcpguard.WithMetrics(metrics),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{
			TrustedProxyHeaders: true,
			IdentityExtractor:   extractIdentity,
			BusinessExtractor:   extractBusiness,
		}),
		tcpguard.WithResponseRenderer(func(sec *tcpguard.Context, decision tcpguard.Decision) tcpguard.DecisionResponse {
			return tcpguard.DecisionResponse{
				Status: httpStatus(decision.Effect),
				Headers: map[string]string{
					"Content-Type":     "application/json",
					"X-TCPGuard-Risk":  strconv.FormatFloat(decision.Risk.Score, 'f', 0, 64),
					"X-TCPGuard-Trace": sec.Request.ID,
				},
				Body: map[string]any{
					"error":       "request_rejected",
					"effect":      decision.Effect,
					"request_id":  sec.Request.ID,
					"risk_score":  decision.Risk.Score,
					"severity":    decision.Severity,
					"rules":       decision.MatchedRules,
					"explanation": decision.Explanation,
				},
			}
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	reloadable, err := tcpguard.NewReloadableGuard(ctx, *policy, bcl.LoadTCPGuardBundleDir, tcpguard.WithStore(store), tcpguard.WithMetrics(metrics))
	if err != nil {
		log.Fatal(err)
	}
	apiKey := os.Getenv("TCPGUARD_MGMT_API_KEY")
	if apiKey == "" {
		apiKey = "dev-management-key"
	}
	management := tcpguard.NewManagementServer(reloadable, tcpguard.ManagementServerConfig{
		AuthProvider: tcpguard.StaticAPIKeyAuth{
			Keys: map[string]tcpguard.ManagementPrincipal{
				apiKey: {Subject: "local-admin", Roles: []string{"admin"}},
			},
		},
		Authorizer: tcpguard.RoleBasedAuthorizer{
			RolesByRoute: map[tcpguard.ManagementRoute][]string{
				tcpguard.ManagementRouteHealth:           {"admin"},
				tcpguard.ManagementRouteReload:           {"admin"},
				tcpguard.ManagementRouteSimulate:         {"admin"},
				tcpguard.ManagementRouteExplain:          {"admin"},
				tcpguard.ManagementRouteIncidents:        {"admin"},
				tcpguard.ManagementRouteAudit:            {"admin"},
				tcpguard.ManagementRouteAuditVerify:      {"admin"},
				tcpguard.ManagementRouteApprovals:        {"admin"},
				tcpguard.ManagementRouteApprovalsApprove: {"admin"},
				tcpguard.ManagementRouteApprovalsReject:  {"admin"},
			},
		},
		MaxBodyByRoute: map[tcpguard.ManagementRoute]int64{
			tcpguard.ManagementRouteSimulate:         1 << 20,
			tcpguard.ManagementRouteExplain:          1 << 20,
			tcpguard.ManagementRouteApprovalsApprove: 16 << 10,
			tcpguard.ManagementRouteApprovalsReject:  16 << 10,
		},
		ReadTimeout:     2 * time.Second,
		AllowedCIDRs:    []string{"127.0.0.0/8"},
		PerIPRateLimit:  120,
		RateLimitWindow: time.Minute,
	})

	mux := http.NewServeMux()
	mux.Handle("/public", guard.HTTPMiddleware(http.HandlerFunc(writeOK)))
	mux.Handle("/account/login", guard.HTTPMiddleware(http.HandlerFunc(writeOK)))
	mux.Handle("/reports/export", guard.HTTPMiddleware(http.HandlerFunc(writeOK)))
	mux.Handle("/functions/", guard.HTTPMiddleware(http.HandlerFunc(writeOK)))
	mux.Handle("/admin/export", guard.HTTPMiddleware(http.HandlerFunc(writeOK)))
	mux.Handle("/payments/approve", guard.HTTPMiddleware(http.HandlerFunc(writeOK)))
	mux.Handle("/_demo/auth/fail", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec := contextFromRequest(r)
		decision := guard.Evaluate(r.Context(), tcpguard.Event{Type: "auth.login_failed", Source: "http-demo"}, sec)
		writeJSON(w, httpStatus(decision.Effect), decision)
	}))
	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, metrics.Snapshot())
	}))
	mux.Handle("/health", management)
	mux.Handle("/reload", management)
	mux.Handle("/simulate", management)
	mux.Handle("/explain", management)
	mux.Handle("/incidents", management)
	mux.Handle("/audit", management)
	mux.Handle("/audit/verify", management)
	mux.Handle("/approvals", management)
	mux.Handle("/approvals/approve", management)
	mux.Handle("/approvals/reject", management)

	log.Printf("tcpguard net/http demo listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func extractIdentity(r *http.Request, sec *tcpguard.Context) {
	sec.Identity.ID = r.Header.Get("X-User-ID")
	sec.Identity.Role = r.Header.Get("X-User-Role")
	sec.Identity.Tenant = r.Header.Get("X-Tenant-ID")
	sec.Tenant.ID = r.Header.Get("X-Tenant-ID")
	sec.Session.ID = r.Header.Get("X-Session-ID")
	sec.Session.DeviceID = r.Header.Get("X-Device-ID")
	sec.Session.UserAgent = r.Header.Get("X-Previous-User-Agent")
	sec.Session.PreviousCountry = r.Header.Get("X-Previous-Country")
	sec.Session.NewDevice = r.Header.Get("X-New-Device") == "true"
	sec.Device.ID = sec.Session.DeviceID
	sec.Device.New = sec.Session.NewDevice
	if country := r.Header.Get("X-Country"); country != "" {
		sec.Network.Country = country
		sec.Network.CountryCode = country
	}
}

func extractBusiness(r *http.Request, sec *tcpguard.Context) {
	sec.Business.Action = r.Header.Get("X-Business-Action")
	sec.Business.Entity = r.Header.Get("X-Business-Entity")
	sec.Business.Workflow = r.Header.Get("X-Workflow")
	sec.Business.Sensitivity = r.Header.Get("X-Sensitivity")
	if raw := r.Header.Get("X-Business-Amount"); raw != "" {
		sec.Business.Amount, _ = strconv.ParseFloat(raw, 64)
	}
	sec.Business.OutsideHours = r.Header.Get("X-Outside-Hours") == "true"
}

func contextFromRequest(r *http.Request) *tcpguard.Context {
	sec := &tcpguard.Context{
		Request: tcpguard.RequestContext{
			ID:        firstNonEmpty(r.Header.Get("X-Request-ID"), "demo-"+strconv.FormatInt(time.Now().UnixNano(), 10)),
			Method:    r.Method,
			Path:      r.URL.Path,
			Headers:   map[string]string{},
			Query:     map[string]string{},
			UserAgent: r.UserAgent(),
		},
		Network:  tcpguard.NetworkContext{IP: firstNonEmpty(r.Header.Get("X-Forwarded-For"), r.RemoteAddr)},
		Runtime:  tcpguard.RuntimeContext{Timestamp: time.Now().UTC()},
		Security: map[string]any{},
		Rate:     map[string]any{},
	}
	for key, values := range r.Header {
		sec.Request.Headers[key] = strings.Join(values, ",")
	}
	for key, values := range r.URL.Query() {
		sec.Request.Query[key] = strings.Join(values, ",")
	}
	extractIdentity(r, sec)
	extractBusiness(r, sec)
	return sec
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func writeOK(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": r.URL.Path})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func httpStatus(effect tcpguard.DecisionEffect) int {
	switch effect {
	case tcpguard.DecisionBlock, tcpguard.DecisionRevoke:
		return http.StatusForbidden
	case tcpguard.DecisionThrottle:
		return http.StatusTooManyRequests
	case tcpguard.DecisionChallenge:
		return http.StatusUnauthorized
	default:
		return http.StatusOK
	}
}
