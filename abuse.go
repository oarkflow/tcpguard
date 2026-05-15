package tcpguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type AbuseDetector struct {
	Store                        SecurityStore
	Window                       time.Duration
	AuthIPFailureThreshold       int64
	AuthUserFailureThreshold     int64
	PasswordSprayUserThreshold   int64
	APIKeyIPThreshold            int64
	APIKeyUserThreshold          int64
	ScanPathThreshold            int64
	ExportThreshold              int64
	FunctionInvokeThreshold      int64
	UserAgentRotationThreshold   int64
	TenantUserThreshold          int64
	AccountEnumerationThreshold  int64
	LargeBodyThreshold           int64
	PaymentUserAmountThreshold   float64
	PaymentTenantAmountThreshold float64
	ProfileRiskThreshold         float64
}

func NewAbuseDetector(store SecurityStore) AbuseDetector {
	return AbuseDetector{
		Store:                        store,
		Window:                       10 * time.Minute,
		AuthIPFailureThreshold:       20,
		AuthUserFailureThreshold:     8,
		PasswordSprayUserThreshold:   10,
		APIKeyIPThreshold:            5,
		APIKeyUserThreshold:          5,
		ScanPathThreshold:            40,
		ExportThreshold:              10,
		FunctionInvokeThreshold:      120,
		UserAgentRotationThreshold:   8,
		TenantUserThreshold:          50,
		AccountEnumerationThreshold:  10,
		LargeBodyThreshold:           10 << 20,
		PaymentUserAmountThreshold:   100000,
		PaymentTenantAmountThreshold: 500000,
		ProfileRiskThreshold:         75,
	}
}

func (d AbuseDetector) ID() string { return "abuse" }

func (d AbuseDetector) Detect(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	if sec == nil || d.Store == nil {
		return nil, nil
	}
	d = d.withDefaults()
	var out []Finding
	if isAuthFailure(event) {
		findings, err := d.detectAuthAbuse(ctx, sec, event)
		if err != nil {
			return nil, err
		}
		out = append(out, findings...)
	}
	findings, err := d.detectAccountTakeover(ctx, sec)
	if err != nil {
		return nil, err
	}
	out = append(out, findings...)
	findings, err = d.detectAPIKeySpread(ctx, sec)
	if err != nil {
		return nil, err
	}
	out = append(out, findings...)
	findings, err = d.detectEndpointScanning(ctx, sec, event)
	if err != nil {
		return nil, err
	}
	out = append(out, findings...)
	findings, err = d.detectExportVelocity(ctx, sec, event)
	if err != nil {
		return nil, err
	}
	out = append(out, findings...)
	findings, err = d.detectPaymentVelocity(ctx, sec)
	if err != nil {
		return nil, err
	}
	out = append(out, findings...)
	findings, err = d.detectFunctionAbuse(ctx, sec, event)
	if err != nil {
		return nil, err
	}
	out = append(out, findings...)
	out = append(out, d.detectApplicationAbuse(sec, event)...)
	out = append(out, d.detectAdminAbuse(sec)...)
	return out, nil
}

func (d AbuseDetector) withDefaults() AbuseDetector {
	defaults := NewAbuseDetector(d.Store)
	if d.Window <= 0 {
		d.Window = defaults.Window
	}
	if d.AuthIPFailureThreshold <= 0 {
		d.AuthIPFailureThreshold = defaults.AuthIPFailureThreshold
	}
	if d.AuthUserFailureThreshold <= 0 {
		d.AuthUserFailureThreshold = defaults.AuthUserFailureThreshold
	}
	if d.PasswordSprayUserThreshold <= 0 {
		d.PasswordSprayUserThreshold = defaults.PasswordSprayUserThreshold
	}
	if d.APIKeyIPThreshold <= 0 {
		d.APIKeyIPThreshold = defaults.APIKeyIPThreshold
	}
	if d.APIKeyUserThreshold <= 0 {
		d.APIKeyUserThreshold = defaults.APIKeyUserThreshold
	}
	if d.ScanPathThreshold <= 0 {
		d.ScanPathThreshold = defaults.ScanPathThreshold
	}
	if d.ExportThreshold <= 0 {
		d.ExportThreshold = defaults.ExportThreshold
	}
	if d.FunctionInvokeThreshold <= 0 {
		d.FunctionInvokeThreshold = defaults.FunctionInvokeThreshold
	}
	if d.UserAgentRotationThreshold <= 0 {
		d.UserAgentRotationThreshold = defaults.UserAgentRotationThreshold
	}
	if d.TenantUserThreshold <= 0 {
		d.TenantUserThreshold = defaults.TenantUserThreshold
	}
	if d.AccountEnumerationThreshold <= 0 {
		d.AccountEnumerationThreshold = defaults.AccountEnumerationThreshold
	}
	if d.LargeBodyThreshold <= 0 {
		d.LargeBodyThreshold = defaults.LargeBodyThreshold
	}
	if d.PaymentUserAmountThreshold <= 0 {
		d.PaymentUserAmountThreshold = defaults.PaymentUserAmountThreshold
	}
	if d.PaymentTenantAmountThreshold <= 0 {
		d.PaymentTenantAmountThreshold = defaults.PaymentTenantAmountThreshold
	}
	if d.ProfileRiskThreshold <= 0 {
		d.ProfileRiskThreshold = defaults.ProfileRiskThreshold
	}
	return d
}

func (d AbuseDetector) detectAuthAbuse(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	var out []Finding
	ipFailures, err := d.incrCounter(ctx, "abuse:auth:ip:"+stableKey(sec.Network.IP))
	if err != nil {
		return nil, err
	}
	userFailures, err := d.incrCounter(ctx, "abuse:auth:user:"+stableKey(sec.Identity.ID))
	if err != nil {
		return nil, err
	}
	sprayUsers, err := d.addDistinct(ctx, "abuse:auth:ip_users:"+stableKey(sec.Network.IP), sec.Identity.ID)
	if err != nil {
		return nil, err
	}
	setContextFact(sec, "abuse.auth.ip_failures", ipFailures)
	setContextFact(sec, "abuse.auth.user_failures", userFailures)
	setContextFact(sec, "abuse.auth.distinct_users", sprayUsers)
	if ipFailures >= d.AuthIPFailureThreshold || userFailures >= d.AuthUserFailureThreshold {
		out = append(out, finding("credential_stuffing", 80, "authentication failure velocity indicates credential stuffing"))
	}
	if sprayUsers >= d.PasswordSprayUserThreshold {
		out = append(out, finding("password_spray", 78, "authentication failures span many users from one source"))
	}
	if isAccountEnumeration(sec, event) && sprayUsers >= d.AccountEnumerationThreshold {
		setContextFact(sec, "abuse.enumeration.distinct_users", sprayUsers)
		out = append(out, finding("account_enumeration", 74, "authentication attempts indicate account enumeration"))
	}
	return out, nil
}

func (d AbuseDetector) detectAccountTakeover(ctx context.Context, sec *Context) ([]Finding, error) {
	profileRisk, err := d.profileRisk(ctx, "user", sec.Identity.ID)
	if err != nil {
		return nil, err
	}
	newDevice := sec.Session.NewDevice || sec.Device.New
	countryChanged := sec.Session.CountryChanged || (sec.Session.PreviousCountry != "" && sec.Network.Country != "" && sec.Session.PreviousCountry != sec.Network.Country)
	uaChanged := sec.Session.UserAgentChanged || (sec.Session.UserAgent != "" && sec.Request.UserAgent != "" && sec.Session.UserAgent != sec.Request.UserAgent)
	setContextFact(sec, "abuse.signals.new_device", newDevice)
	setContextFact(sec, "abuse.signals.country_changed", countryChanged)
	setContextFact(sec, "abuse.signals.user_agent_changed", uaChanged)
	setContextFact(sec, "abuse.signals.profile_risk", profileRisk)
	score := 0
	if newDevice {
		score += 1
	}
	if countryChanged {
		score += 1
	}
	if uaChanged {
		score += 1
	}
	if sec.Network.Proxy || sec.Network.VPN || sec.Network.Tor {
		score += 1
		setContextFact(sec, "abuse.signals.anonymous_network", true)
	}
	if profileRisk >= d.ProfileRiskThreshold {
		score += 1
	}
	setContextFact(sec, "abuse.signals.account_takeover_score", score)
	if score >= 2 {
		return []Finding{finding("account_takeover_risk", 82, "account takeover signals were observed")}, nil
	}
	return nil, nil
}

func (d AbuseDetector) detectAPIKeySpread(ctx context.Context, sec *Context) ([]Finding, error) {
	apiKey := firstNonEmpty(headerValue(sec.Request.Headers, "X-API-Key"), headerValue(sec.Request.Headers, "Authorization"))
	if apiKey == "" || sec.Network.IP == "" {
		return nil, nil
	}
	var out []Finding
	count, err := d.addDistinct(ctx, "abuse:api_key:ips:"+stableKey(apiKey), sec.Network.IP)
	if err != nil {
		return nil, err
	}
	setContextFact(sec, "abuse.api_key.distinct_ips", count)
	if count >= d.APIKeyIPThreshold {
		out = append(out, finding("api_key_ip_spread", 72, "API key is used from many source IPs"))
	}
	if sec.Identity.ID != "" {
		users, err := d.addDistinct(ctx, "abuse:api_key:users:"+stableKey(apiKey), sec.Identity.ID)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.api_key.distinct_users", users)
		if users >= d.APIKeyUserThreshold {
			out = append(out, finding("api_key_user_spread", 74, "API key is used by many users"))
		}
	}
	return out, nil
}

func (d AbuseDetector) detectEndpointScanning(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	if sec.Request.Path == "" || !strings.HasPrefix(event.Type, "request.") {
		return nil, nil
	}
	var out []Finding
	var maxCount int64
	if sec.Network.IP != "" {
		count, err := d.addDistinct(ctx, "abuse:scan:ip_paths:"+stableKey(sec.Network.IP), sec.Request.Method+" "+sec.Request.Path)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.scan.ip_distinct_paths", count)
		maxCount = count
	}
	if sec.Identity.ID != "" {
		count, err := d.addDistinct(ctx, "abuse:scan:user_paths:"+stableKey(sec.Identity.ID), sec.Request.Method+" "+sec.Request.Path)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.scan.user_distinct_paths", count)
		if count > maxCount {
			maxCount = count
		}
	}
	setContextFact(sec, "abuse.scan.distinct_paths", maxCount)
	if maxCount >= d.ScanPathThreshold {
		out = append(out, finding("endpoint_scanning", 70, "source visited many distinct endpoints"))
	}
	if sec.Network.IP != "" && sec.Request.UserAgent != "" {
		uas, err := d.addDistinct(ctx, "abuse:client:user_agents:"+stableKey(sec.Network.IP), sec.Request.UserAgent)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.client.distinct_user_agents", uas)
		if uas >= d.UserAgentRotationThreshold {
			out = append(out, finding("user_agent_rotation", 62, "source rotated many user agents"))
		}
	}
	tenant := firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant)
	if tenant != "" && sec.Identity.ID != "" {
		users, err := d.addDistinct(ctx, "abuse:tenant:users:"+stableKey(tenant), sec.Identity.ID)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.tenant.distinct_users", users)
		if users >= d.TenantUserThreshold {
			out = append(out, finding("tenant_user_fanout", 68, "tenant activity spans many users in a short window"))
		}
	}
	return out, nil
}

func (d AbuseDetector) detectExportVelocity(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	if !isExportActivity(sec, event) {
		return nil, nil
	}
	entity := firstNonEmpty(sec.Identity.ID, sec.Network.IP, sec.Tenant.ID)
	n, err := d.incrCounter(ctx, "abuse:export:"+stableKey(entity))
	if err != nil {
		return nil, err
	}
	setContextFact(sec, "abuse.export.count", n)
	setContextFact(sec, "abuse.data_export.count", n)
	if sec.Request.BodySize >= d.LargeBodyThreshold {
		setContextFact(sec, "abuse.data_export.large_body", true)
		return []Finding{finding("large_export_body", 70, "large export payload detected")}, nil
	}
	if n >= d.ExportThreshold {
		return []Finding{finding("export_velocity", 76, "data export velocity exceeded expected limits")}, nil
	}
	return nil, nil
}

func (d AbuseDetector) detectPaymentVelocity(ctx context.Context, sec *Context) ([]Finding, error) {
	if sec.Business.Amount <= 0 || !isPaymentActivity(sec) {
		return nil, nil
	}
	var out []Finding
	if sec.Identity.ID != "" {
		total, err := d.addAmount(ctx, "abuse:payment:user:"+stableKey(sec.Identity.ID), sec.Business.Amount)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.payment.user_amount", total)
		if total >= d.PaymentUserAmountThreshold {
			out = append(out, finding("payment_velocity", 84, "user payment velocity exceeded expected limits"))
		}
	}
	tenant := firstNonEmpty(sec.Tenant.ID, sec.Identity.Tenant)
	if tenant != "" {
		total, err := d.addAmount(ctx, "abuse:payment:tenant:"+stableKey(tenant), sec.Business.Amount)
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.payment.tenant_amount", total)
		if total >= d.PaymentTenantAmountThreshold {
			out = append(out, finding("tenant_payment_velocity", 82, "tenant payment velocity exceeded expected limits"))
		}
	}
	return out, nil
}

func (d AbuseDetector) detectFunctionAbuse(ctx context.Context, sec *Context, event Event) ([]Finding, error) {
	name := functionName(sec, event)
	if name == "" {
		return nil, nil
	}
	entity := firstNonEmpty(sec.Identity.ID, sec.Network.IP, "anonymous")
	n, err := d.incrCounter(ctx, "abuse:function:invoke:"+stableKey(entity+":"+name))
	if err != nil {
		return nil, err
	}
	setContextFact(sec, "abuse.function.name", name)
	setContextFact(sec, "abuse.function.invocations", n)
	setContextFact(sec, "abuse.fn.name", name)
	setContextFact(sec, "abuse.fn.invocations", n)
	var out []Finding
	if n >= d.FunctionInvokeThreshold {
		out = append(out, finding("function_invocation_velocity", 72, "function invocation velocity exceeded expected limits"))
	}
	if eventFieldBool(event, "error") || eventFieldString(event, "status") == "error" || eventFieldString(event, "status") == "failed" {
		errors, err := d.incrCounter(ctx, "abuse:function:error:"+stableKey(entity+":"+name))
		if err != nil {
			return nil, err
		}
		setContextFact(sec, "abuse.function.errors", errors)
		setContextFact(sec, "abuse.fn.errors", errors)
		if errors >= 3 {
			out = append(out, finding("function_error_abuse", 64, "function error velocity indicates probing or misuse"))
		}
	}
	return out, nil
}

func (d AbuseDetector) detectApplicationAbuse(sec *Context, event Event) []Finding {
	surface := strings.ToLower(requestSurface(sec, event))
	var out []Finding
	if containsAny(surface, "../", "..%2f", "%2e%2e", "/etc/passwd", "\\..\\") {
		setContextFact(sec, "abuse.application.path_traversal", true)
		out = append(out, finding("path_traversal_probe", 76, "path traversal probe detected"))
	}
	if containsAny(surface, " union select ", "' or '1'='1", "\" or \"1\"=\"1", "sleep(", "benchmark(", "information_schema") {
		setContextFact(sec, "abuse.application.injection_probe", true)
		out = append(out, finding("injection_probe", 78, "injection probe detected"))
	}
	if containsAny(surface, "<script", "javascript:", "onerror=", "onload=") {
		setContextFact(sec, "abuse.application.xss_probe", true)
		out = append(out, finding("xss_probe", 66, "cross-site scripting probe detected"))
	}
	if containsAny(surface, "169.254.169.254", "metadata.google.internal", "localhost/admin", "127.0.0.1/admin") {
		setContextFact(sec, "abuse.application.ssrf_probe", true)
		out = append(out, finding("ssrf_probe", 80, "server-side request forgery probe detected"))
	}
	return out
}

func (d AbuseDetector) detectAdminAbuse(sec *Context) []Finding {
	action := strings.ToLower(sec.Request.Method + " " + sec.Request.Path + " " + sec.Business.Action + " " + sec.Business.Workflow)
	destructive := containsAny(action, "delete", "disable", "lock", "ban", "revoke", "permission", "role", "sudo")
	privileged := sec.Identity.Role == "admin" || sec.Identity.Role == "super_admin" || stringIn("admin", sec.Identity.Roles) || stringIn("super_admin", sec.Identity.Roles)
	if !destructive || !privileged {
		return nil
	}
	setContextFact(sec, "abuse.admin.destructive", true)
	if sec.Business.OutsideHours || sec.Session.NewDevice || sec.Device.New || sec.Session.CountryChanged {
		return []Finding{finding("destructive_admin_abuse", 86, "destructive admin action has abuse signals")}
	}
	return []Finding{finding("destructive_admin_action", 60, "destructive admin action observed")}
}

func (d AbuseDetector) incrCounter(ctx context.Context, key string) (int64, error) {
	if strings.HasSuffix(key, ":") {
		return 0, nil
	}
	return d.Store.Incr(ctx, key, d.Window)
}

func (d AbuseDetector) addAmount(ctx context.Context, key string, amount float64) (float64, error) {
	if strings.HasSuffix(key, ":") {
		return 0, nil
	}
	var total float64
	if data, found, err := d.Store.Get(ctx, key); err != nil {
		return 0, err
	} else if found {
		_ = json.Unmarshal(data, &total)
	}
	total += amount
	data, _ := json.Marshal(total)
	return total, d.Store.Set(ctx, key, data, d.Window)
}

func (d AbuseDetector) addDistinct(ctx context.Context, key, value string) (int64, error) {
	if strings.HasSuffix(key, ":") || value == "" {
		return 0, nil
	}
	values := map[string]bool{}
	if data, found, err := d.Store.Get(ctx, key); err != nil {
		return 0, err
	} else if found {
		_ = json.Unmarshal(data, &values)
	}
	values[value] = true
	data, _ := json.Marshal(values)
	return int64(len(values)), d.Store.Set(ctx, key, data, d.Window)
}

func (d AbuseDetector) profileRisk(ctx context.Context, entity, id string) (float64, error) {
	if entity == "" || id == "" {
		return 0, nil
	}
	data, found, err := d.Store.Get(ctx, "profile:"+entity+":"+id)
	if err != nil || !found {
		return 0, err
	}
	var profile EntityProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return 0, nil
	}
	return profile.RiskScore, nil
}

func isAuthFailure(event Event) bool {
	switch event.Type {
	case "auth.login_failed", "auth.failure", "auth.failed", "auth.password_failed":
		return true
	}
	if value, ok := event.Fields.Get("success"); ok {
		if b, ok := value.(bool); ok {
			return !b
		}
	}
	return false
}

func isAccountEnumeration(sec *Context, event Event) bool {
	if eventFieldBool(event, "user_exists") {
		return false
	}
	if value, ok := event.Fields.Get("user_exists"); ok {
		if b, ok := value.(bool); ok {
			return !b
		}
	}
	surface := strings.ToLower(sec.Request.Path + " " + sec.Business.Action + " " + event.Type)
	return strings.Contains(surface, "login") || strings.Contains(surface, "password") || strings.Contains(surface, "reset") || strings.Contains(surface, "signup")
}

func isExportActivity(sec *Context, event Event) bool {
	action := strings.ToLower(sec.Business.Action + " " + sec.Business.Workflow + " " + sec.Request.Path + " " + event.Type)
	return strings.Contains(action, "export") || strings.Contains(action, "download")
}

func isPaymentActivity(sec *Context) bool {
	action := strings.ToLower(sec.Business.Action + " " + sec.Business.Workflow + " " + sec.Business.Entity)
	return strings.Contains(action, "payment") || strings.Contains(action, "transfer") || strings.Contains(action, "payout")
}

func functionName(sec *Context, event Event) string {
	name := firstNonEmpty(
		eventFieldString(event, "function"),
		eventFieldString(event, "function_name"),
		headerValue(sec.Request.Headers, "X-Function-Name"),
	)
	if name != "" {
		return name
	}
	if strings.HasPrefix(event.Type, "function.") {
		return firstNonEmpty(sec.Business.Action, sec.Request.Path)
	}
	if strings.Contains(sec.Request.Path, "/functions/") || strings.Contains(sec.Request.Path, "/function/") {
		parts := strings.Split(strings.Trim(sec.Request.Path, "/"), "/")
		for i, part := range parts {
			if (part == "functions" || part == "function") && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func requestSurface(sec *Context, event Event) string {
	var b strings.Builder
	b.WriteString(sec.Request.Path)
	b.WriteByte(' ')
	b.WriteString(sec.Request.UserAgent)
	for key, value := range sec.Request.Query {
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(value)
	}
	for key, value := range event.Fields {
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(stringify(value))
	}
	return b.String()
}

func eventFieldString(event Event, key string) string {
	if event.Fields == nil {
		return ""
	}
	value, ok := event.Fields.Get(key)
	if !ok {
		return ""
	}
	return stringify(value)
}

func eventFieldBool(event Event, key string) bool {
	if event.Fields == nil {
		return false
	}
	value, ok := event.Fields.Get(key)
	if !ok {
		return false
	}
	b, _ := value.(bool)
	return b
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func stableKey(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func DefaultAbuseThreatModel() ThreatModelDefinition {
	return ThreatModelDefinition{
		ID: "abuse-default",
		Categories: map[string][]string{
			"account_takeover":    {"account_takeover_risk", "session_country_changed", "session_user_agent_changed", "new_device_login"},
			"bot_abuse":           {"credential_stuffing", "password_spray", "endpoint_scanning", "suspicious_user_agent"},
			"api_abuse":           {"api_key_ip_spread", "api_key_user_spread", "user_agent_rotation", "tenant_user_fanout"},
			"application_abuse":   {"path_traversal_probe", "injection_probe", "xss_probe", "ssrf_probe"},
			"function_abuse":      {"function_invocation_velocity", "function_error_abuse"},
			"replay":              {"nonce_reused", "timestamp_skew", "invalid_signature"},
			"data_exfiltration":   {"export_velocity", "large_export_body", "sensitive_export", "debug_query_probe"},
			"payment_fraud":       {"payment_velocity", "tenant_payment_velocity", "high_value_action"},
			"authorization_abuse": {"destructive_admin_abuse", "destructive_admin_action", "after_hours_admin_access", "admin_department_mismatch", "sensitive_endpoint_access"},
			"denial_of_service":   {"rate_limit_abuse", "user_rate_limit_abuse", "tenant_rate_limit_abuse", "endpoint_rate_limit_abuse"},
		},
	}
}
