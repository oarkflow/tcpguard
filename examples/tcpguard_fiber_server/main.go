package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/condition/tcpguard"
	"github.com/oarkflow/condition/tcpguard/bcl"
	_ "modernc.org/sqlite"
)

const hmacSecret = "tcpguard-demo-secret"

func main() {
	ctx := context.Background()
	dir := exampleDir()

	bundle, err := bcl.LoadTCPGuardBundleFile(ctx, filepath.Join(dir, "tcpguard.bcl"))
	must("load tcpguard BCL", err)
	printBundleSummary(bundle)

	store := tcpguard.NewMemoryStore()
	accountDB := openAccountDB()
	guard, err := tcpguard.New(
		tcpguard.WithBundle(bundle),
		tcpguard.WithStore(store),
		tcpguard.WithDataSource(tcpguard.MemoryDataSource{
			SourceID: "demo-cache",
			Values: map[string]any{
				"ban:user:banned-user": map[string]any{"reason": "manual SOC ban"},
			},
		}),
		tcpguard.WithSQLDataSource("account-db", accountDB),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{
			TrustedProxyHeaders: true,
			IdentityExtractor:   extractIdentity,
			BusinessExtractor:   extractBusiness,
		}),
		tcpguard.WithHMACSecretProvider(func(sec *tcpguard.Context) []byte {
			if sec.Request.Path == "/api/v1/transfers" || sec.Request.Headers["X-TCPGuard-Signature"] != "" {
				return []byte(hmacSecret)
			}
			return nil
		}),
	)
	must("create tcpguard", err)

	app := fiber.New()

	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{
			"service": "tcpguard Fiber middleware demo",
			"try": []string{
				"GET /public",
				"GET /public?debug=true",
				"POST /admin/users with X-User-Role: admin and X-Outside-Hours: true",
				"POST /api/v1/transfers with signed headers from /_demo/sign",
				"PUT /api/users/user-2/order/order-9 with X-User-ID: user-1",
			},
		})
	})
	app.Post("/_demo/risk-source", func(c fiber.Ctx) error {
		var req tcpguard.LookupRequest
		_ = c.Bind().Body(&req)
		score := 15
		label := "normal"
		if req.Key == "risky-http" {
			score = 88
			label = "elevated"
		}
		return c.JSON(map[string]any{"score": score, "label": label})
	})

	app.Post("/_demo/sign", func(c fiber.Ctx) error {
		method := c.Query("method", http.MethodPost)
		path := c.Query("path", "/api/v1/transfers")
		body := c.BodyRaw()
		return c.JSON(map[string]any{
			"method":    method,
			"path":      path,
			"signature": sign(method, path, body),
			"nonce":     "nonce-" + strconv.FormatInt(time.Now().UnixNano(), 10),
			"timestamp": time.Now().Unix(),
			"secret":    "server-side only in real deployments",
		})
	})

	app.Get("/_demo/approvals", func(c fiber.Ctx) error {
		status := tcpguard.ApprovalStatus(c.Query("status"))
		records, err := guard.ListApprovals(c.Context(), status)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(errorBody(err))
		}
		return c.JSON(records)
	})
	app.Post("/_demo/approvals/:id/approve", func(c fiber.Ctx) error {
		record, err := guard.Approve(c.Context(), c.Params("id"), c.Get("X-Approver", "security-admin"), c.Get("X-Reason", "approved from Fiber demo"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(errorBody(err))
		}
		return c.JSON(record)
	})
	app.Post("/_demo/approvals/:id/reject", func(c fiber.Ctx) error {
		record, err := guard.Reject(c.Context(), c.Params("id"), c.Get("X-Approver", "security-admin"), c.Get("X-Reason", "rejected from Fiber demo"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(errorBody(err))
		}
		return c.JSON(record)
	})
	app.Get("/_demo/incidents", func(c fiber.Ctx) error {
		incidents, err := store.ListIncidents(c.Context())
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(errorBody(err))
		}
		return c.JSON(incidents)
	})
	app.Get("/_demo/audit", func(c fiber.Ctx) error {
		envelopes, err := store.ListAuditEnvelopes(c.Context())
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(errorBody(err))
		}
		if err := tcpguard.VerifyAuditChain(envelopes); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(map[string]any{"valid": false, "error": err.Error(), "envelopes": envelopes})
		}
		return c.JSON(map[string]any{"valid": true, "envelopes": envelopes})
	})

	app.Use(guard.Middleware())

	app.Get("/public", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "message": "clean request allowed", "risk": c.GetRespHeader("X-TCPGuard-Risk")})
	})
	app.Get("/geo-restricted", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "message": "geo-restricted request allowed"})
	})
	app.Post("/admin/users", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "message": "admin change accepted"})
	})
	app.Post("/api/v1/reports/export", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "message": "export started"})
	})
	app.Put("/api/users/:id/order/:order_id", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "user": c.Params("id"), "order": c.Params("order_id")})
	})
	app.Post("/api/v1/payments/approve", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "message": "payment approved"})
	})
	app.Post("/api/v1/transfers", func(c fiber.Ctx) error {
		return c.JSON(map[string]any{"ok": true, "message": "signed transfer accepted"})
	})

	addr := ":18181"
	fmt.Printf("TCPGuard Fiber demo listening on http://127.0.0.1%s\n", addr)
	fmt.Println("Open examples/tcpguard_fiber_server/README.md for curl scenarios.")
	log.Fatal(app.Listen(addr))
}

func extractIdentity(r *http.Request, sec *tcpguard.Context) {
	sec.Identity.ID = firstNonEmpty(r.Header.Get("X-User-ID"), "anonymous")
	sec.Identity.Role = firstNonEmpty(r.Header.Get("X-User-Role"), "member")
	sec.Identity.Tenant = firstNonEmpty(r.Header.Get("X-Tenant-ID"), "demo-bank")
	sec.Tenant.ID = sec.Identity.Tenant
	sec.Session.ID = firstNonEmpty(r.Header.Get("X-Session-ID"), "session-"+sec.Identity.ID)
	sec.Session.DeviceID = r.Header.Get("X-Device-ID")
	sec.Session.UserAgent = r.Header.Get("X-Previous-User-Agent")
	sec.Session.PreviousCountry = r.Header.Get("X-Previous-Country")
	sec.Session.NewDevice = boolHeader(r, "X-New-Device")
	sec.Device.ID = sec.Session.DeviceID
	sec.Device.New = sec.Session.NewDevice
	if country := r.Header.Get("X-Country"); country != "" {
		sec.Network.Country = country
		sec.Network.CountryCode = country
	}
	sec.Network.ASN = r.Header.Get("X-ASN")
}

func extractBusiness(r *http.Request, sec *tcpguard.Context) {
	sec.Business.Action = r.Header.Get("X-Business-Action")
	sec.Business.Entity = r.Header.Get("X-Business-Entity")
	sec.Business.Workflow = r.Header.Get("X-Workflow")
	sec.Business.Sensitivity = r.Header.Get("X-Sensitivity")
	sec.Business.OutsideHours = boolHeader(r, "X-Outside-Hours") || sec.Business.OutsideHours
	if amount := r.Header.Get("X-Business-Amount"); amount != "" {
		sec.Business.Amount, _ = strconv.ParseFloat(amount, 64)
	}
}

func openAccountDB() *sql.DB {
	db, err := sql.Open("sqlite", ":memory:")
	must("open account sqlite", err)
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		CREATE TABLE accounts (id TEXT PRIMARY KEY, status TEXT, locked BOOLEAN);
		INSERT INTO accounts (id, status, locked) VALUES
			('manager-1', 'active', false),
			('user-1', 'active', false),
			('locked-user', 'locked', true),
			('risky-http', 'active', false),
			('banned-user', 'active', false);
	`)
	must("seed account sqlite", err)
	return db
}

func boolHeader(r *http.Request, key string) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get(key))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func sign(method, path string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(path))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func errorBody(err error) map[string]any {
	return map[string]any{"error": err.Error()}
}

func printBundleSummary(bundle tcpguard.Bundle) {
	fmt.Println()
	fmt.Println("TCPGuard policy bundle")
	printKeyValueTable([][2]string{
		{"name", bundle.Name},
		{"version", bundle.Version},
		{"mode", string(bundle.Mode)},
		{"timezone", bundle.Timezone},
		{"rules", strconv.Itoa(len(bundle.Rules))},
		{"datasources", strconv.Itoa(len(bundle.DataSources))},
		{"lookups", strconv.Itoa(len(bundle.Lookups))},
		{"actions", strconv.Itoa(len(bundle.Actions))},
		{"detectors", strconv.Itoa(len(bundle.Detectors))},
		{"intel_feeds", strconv.Itoa(len(bundle.IntelFeeds))},
		{"triggers", strconv.Itoa(len(bundle.DerivedEvents))},
	})
	printDataSourceTable(bundle.DataSources)
	printLookupTable(bundle.Lookups)
	printRuleTable(bundle.Rules)
	fmt.Println()
}

func printKeyValueTable(rows [][2]string) {
	w := newTabWriter()
	fmt.Fprintln(w, "KEY\tVALUE")
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%s\n", row[0], emptyDash(row[1]))
	}
	_ = w.Flush()
}

func printDataSourceTable(sources []tcpguard.DataSourceDefinition) {
	if len(sources) == 0 {
		return
	}
	w := newTabWriter()
	fmt.Fprintln(w, "\nDATASOURCES")
	fmt.Fprintln(w, "ID\tTYPE\tKEY\tTARGET")
	for _, source := range sources {
		target := firstNonEmpty(source.Path, source.URL, source.DSN, source.Prefix, "-")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", source.ID, emptyDash(source.Type), emptyDash(source.Key), target)
	}
	_ = w.Flush()
}

func printLookupTable(lookups []tcpguard.LookupDefinition) {
	if len(lookups) == 0 {
		return
	}
	w := newTabWriter()
	fmt.Fprintln(w, "\nLOOKUPS")
	fmt.Fprintln(w, "ID\tSOURCE\tMODE\tFALLBACK\tOUTPUTS")
	for _, lookup := range lookups {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", lookup.ID, lookup.Source, emptyDash(lookup.Mode), emptyDash(string(lookup.Fallback.Policy)), joinMapValues(lookup.Outputs))
	}
	_ = w.Flush()
}

func printRuleTable(rules []tcpguard.Rule) {
	if len(rules) == 0 {
		return
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority > rules[j].Priority
	})
	w := newTabWriter()
	fmt.Fprintln(w, "\nRULES")
	fmt.Fprintln(w, "PRIORITY\tSTATUS\tRULE\tTRIGGERS\tPATHS\tACTIONS\tAPPROVAL")
	for _, rule := range rules {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			rule.Priority,
			emptyDash(string(rule.Status)),
			rule.ID,
			emptyDash(strings.Join(rule.Triggers, ",")),
			emptyDash(strings.Join(rule.Scope.Paths, ",")),
			emptyDash(formatRuleActions(rule.Actions)),
			formatApproval(rule.Approval),
		)
	}
	_ = w.Flush()
}

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func formatRuleActions(actions map[tcpguard.Severity][]tcpguard.ActionRef) string {
	if len(actions) == 0 {
		return "-"
	}
	severities := make([]string, 0, len(actions))
	for severity := range actions {
		severities = append(severities, string(severity))
	}
	sort.Strings(severities)
	parts := make([]string, 0, len(severities))
	for _, severity := range severities {
		refs := actions[tcpguard.Severity(severity)]
		ids := make([]string, 0, len(refs))
		for _, ref := range refs {
			ids = append(ids, ref.ID)
		}
		parts = append(parts, severity+":"+strings.Join(ids, "+"))
	}
	return strings.Join(parts, ";")
}

func formatApproval(approval tcpguard.Approval) string {
	if !approval.Required {
		return "-"
	}
	if len(approval.Approvers) == 0 {
		return "required"
	}
	return "required:" + strings.Join(approval.Approvers, ",")
}

func joinMapValues(values map[string]string) string {
	if len(values) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"->"+values[key])
	}
	return strings.Join(out, ",")
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func exampleDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("resolve example directory")
	}
	return filepath.Dir(file)
}

func must(label string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}
}
