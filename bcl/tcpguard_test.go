package bcl_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/condition/tcpguard"
	"github.com/oarkflow/condition/tcpguard/bcl"
)

func TestParseTCPGuardBundle(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
guard "tcpguard-main" {
  mode enforce
  version "2026.05.13"
}

action "notify_soc" {
  type webhook
  endpoint "http://127.0.0.1:9090/security"
  timeout 5s
}

rule "signed-request-replay-detection" {
  name "Detect duplicate nonce or invalid request signature"
  status active
  priority 300

  scope {
    roles ["admin"]
    methods ["GET", "POST"]
    paths ["/admin/*"]
  }

  trigger {
    on request.received
  }

  when {
    all {
      security.signature.valid equals false
    }
  }

  risk {
    base 80
    add 20 when security.nonce.reused equals true
    max 100
  }

  severity {
    high when risk.score greater_or_equal 75
    critical when risk.score greater_or_equal 90
  }

  actions {
    critical {
      run block
      run notify_soc
    }
  }
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	if bundle.Mode != tcpguard.Enforce {
		t.Fatalf("mode=%s want enforce", bundle.Mode)
	}
	if len(bundle.Rules) != 1 {
		t.Fatalf("rules=%d want 1", len(bundle.Rules))
	}
	rule := bundle.Rules[0]
	if rule.Condition != `security.signature.valid == false` {
		t.Fatalf("condition=%q", rule.Condition)
	}
	if len(rule.Actions[tcpguard.SeverityCritical]) != 2 {
		t.Fatalf("critical actions=%d want 2", len(rule.Actions[tcpguard.SeverityCritical]))
	}
	if got := strings.Join(rule.Scope.Methods, ","); got != "GET,POST" {
		t.Fatalf("methods=%q want GET,POST", got)
	}
	if len(bundle.Actions) != 1 || bundle.Actions[0].Type != "webhook" {
		t.Fatalf("actions=%v", bundle.Actions)
	}
}

func TestLoadTCPGuardBundleDirMergesPolicyPackFiles(t *testing.T) {
	dir := t.TempDir()
	writeTCPGuardFile(t, filepath.Join(dir, "00-guard.bcl"), `
guard "banking-pack" {
  mode enforce
  version "1.0.0"
}
`)
	writeTCPGuardFile(t, filepath.Join(dir, "actions", "webhooks.bcl"), `
action "notify_soc" {
  type webhook
  request {
    endpoint env("SOC_WEBHOOK_URL")
  }
}
`)
	writeTCPGuardFile(t, filepath.Join(dir, "rules", "global.bcl"), `
rule "global-blacklisted-ip" {
  trigger {
    on request.received
  }
  when {
    network.blacklisted equals true
  }
  risk {
    base 95
  }
}
`)
	writeTCPGuardFile(t, filepath.Join(dir, "rules", "endpoints", "admin.bcl"), `
rule "admin-endpoint" {
  scope {
    paths ["/admin/*"]
  }
  trigger {
    on request.received
  }
  when {
    request.path matches "/admin/*"
  }
  risk {
    base 90
  }
}
`)
	writeTCPGuardFile(t, filepath.Join(dir, "rules", "business", "export.bcl"), `
rule "large-export" {
  trigger {
    on business.export
  }
  when {
    business.action equals "report.export"
  }
  risk {
    base 85
  }
}
`)
	writeTCPGuardFile(t, filepath.Join(dir, "intel", "bad_ips.bcl"), `
intel "bad-ip-feed" {
  type file
  path "bad_ips.txt"
  match network.ip
  field network.blacklisted true
  field network.reputation 90
}
`)
	writeTCPGuardFile(t, filepath.Join(dir, "intel", "bad_ips.txt"), "203.0.113.10\n")

	bundle, err := bcl.LoadTCPGuardBundleDir(t.Context(), dir)
	if err != nil {
		t.Fatalf("LoadTCPGuardBundleDir returned error: %v", err)
	}
	if bundle.Name != "banking-pack" || bundle.Mode != tcpguard.Enforce || bundle.Version != "1.0.0" {
		t.Fatalf("bundle metadata=%q %q %q", bundle.Name, bundle.Mode, bundle.Version)
	}
	if len(bundle.Actions) != 1 {
		t.Fatalf("actions=%d want 1", len(bundle.Actions))
	}
	if len(bundle.Rules) != 3 {
		t.Fatalf("rules=%d want 3", len(bundle.Rules))
	}
	if len(bundle.IntelFeeds) != 1 {
		t.Fatalf("intel=%d want 1", len(bundle.IntelFeeds))
	}
	if !filepath.IsAbs(bundle.IntelFeeds[0].Path) {
		t.Fatalf("intel path=%q is not absolute", bundle.IntelFeeds[0].Path)
	}
	if filepath.Base(filepath.Dir(bundle.IntelFeeds[0].Path)) != "intel" {
		t.Fatalf("intel path=%q was not resolved relative to declaring file", bundle.IntelFeeds[0].Path)
	}
}

func TestParseTCPGuardActionRequestAndConditionSemantics(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
action "notify_fraud_team" {
  type webhook
  request {
    endpoint "http://example.local/incidents/{{request.id}}"
    method POST
    headers {
      "Content-Type" "application/json"
      "X-Tenant" "{{tenant.id}}"
    }
    body {
      request "{{request.id}}"
      risk "{{risk.score}}"
      severity "{{severity}}"
      include user.id as user_id
      include tenant.id
      field source "tcpguard"
    }
  }
}

rule "wildcard-and-any" {
  trigger {
    on request.received
  }
  when {
    any {
      request.path matches "/admin/*"
      request.path matches "/api/v1/reports/*"
    }
  }
  risk {
    base 75
  }
  actions {
    high {
      run notify_fraud_team
    }
  }
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	if len(bundle.Actions) != 1 {
		t.Fatalf("actions=%d want 1", len(bundle.Actions))
	}
	action := bundle.Actions[0]
	if action.Request.Endpoint != "http://example.local/incidents/{{request.id}}" {
		t.Fatalf("endpoint=%q", action.Request.Endpoint)
	}
	if action.Request.Headers["X-Tenant"] != "{{tenant.id}}" {
		t.Fatalf("headers=%v", action.Request.Headers)
	}
	if action.Request.Include["user_id"] != "user.id" || action.Request.Include["tenant_id"] != "tenant.id" {
		t.Fatalf("include=%v", action.Request.Include)
	}
	if _, ok := action.Request.Body["risk"].(tcpguard.Placeholder); !ok {
		t.Fatalf("risk body placeholder=%T %[1]v", action.Request.Body["risk"])
	}
	if len(bundle.Rules) != 1 {
		t.Fatalf("rules=%d want 1", len(bundle.Rules))
	}
	if bundle.Rules[0].Condition != `(wildcard_match(request.path, "/admin/*") or wildcard_match(request.path, "/api/v1/reports/*"))` {
		t.Fatalf("condition=%q", bundle.Rules[0].Condition)
	}
}

func TestParseTCPGuardEnvContextSessionRefs(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
action "notify" {
  type webhook
  request {
    endpoint env("SOC_WEBHOOK_URL")
    headers {
      "Authorization" "Bearer {{env.SOC_TOKEN}}"
      "X-Session" "{{session.id}}"
      "X-Tenant" "{{context(\"tenant.id\")}}"
    }
    body {
      request context("request.id")
      session session("id")
      tenant context("tenant.id")
      token env("SOC_TOKEN")
      field source env("SOURCE_NAME")
    }
  }
}
rule "env-condition" {
  trigger {
    on request.received
  }
  when {
    env("TCPGUARD_TEST_MODE") equals "on"
  }
  risk {
    base 90
  }
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	action := bundle.Actions[0]
	if action.Request.Endpoint != `{{env("SOC_WEBHOOK_URL")}}` {
		t.Fatalf("endpoint=%q", action.Request.Endpoint)
	}
	if action.Request.Headers["X-Session"] != "{{session.id}}" {
		t.Fatalf("headers=%v", action.Request.Headers)
	}
	if _, ok := action.Request.Body["request"].(tcpguard.ContextRef); !ok {
		t.Fatalf("request ref=%T", action.Request.Body["request"])
	}
	if _, ok := action.Request.Body["session"].(tcpguard.SessionRef); !ok {
		t.Fatalf("session ref=%T", action.Request.Body["session"])
	}
	if _, ok := action.Request.Body["token"].(tcpguard.EnvRef); !ok {
		t.Fatalf("token ref=%T", action.Request.Body["token"])
	}
	if _, ok := action.Request.Fields["source"].(tcpguard.EnvRef); !ok {
		t.Fatalf("source ref=%T", action.Request.Fields["source"])
	}
}

func TestParseTCPGuardEnvContextSessionRefsWithDefault(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
action "notify" {
  type webhook
  request {
    endpoint env("SOC_WEBHOOK_URL", "https://fallback.example/hook")
    headers {
      "X-Session" "{{session("id", "anon")}}"
      "X-Tenant" "{{context("tenant.id", "public")}}"
    }
    body {
      token env("SOC_TOKEN", "missing")
      tenant context("tenant.id", "public")
      session session("id", "anon")
    }
  }
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	action := bundle.Actions[0]
	if action.Request.Endpoint != `{{env("SOC_WEBHOOK_URL", "https://fallback.example/hook")}}` {
		t.Fatalf("endpoint=%q", action.Request.Endpoint)
	}
	if got := action.Request.Headers["X-Session"]; got != `{{session("id", "anon")}}` {
		t.Fatalf("session header=%q", got)
	}
	if got := action.Request.Headers["X-Tenant"]; got != `{{context("tenant.id", "public")}}` {
		t.Fatalf("tenant header=%q", got)
	}
	if _, ok := action.Request.Body["token"].(tcpguard.EnvRef); !ok {
		t.Fatalf("token ref=%T", action.Request.Body["token"])
	}
	if _, ok := action.Request.Body["tenant"].(tcpguard.ContextRef); !ok {
		t.Fatalf("tenant ref=%T", action.Request.Body["tenant"])
	}
	if _, ok := action.Request.Body["session"].(tcpguard.SessionRef); !ok {
		t.Fatalf("session ref=%T", action.Request.Body["session"])
	}
}

func TestParseTCPGuardDetectorBaselineAndSafety(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
policy_safety {
  max_detector_timeout 25ms
  max_action_timeout 2s
  max_retry_count 2
  action_allowlist ["block", "webhook"]
  command_enabled false
}

detector "sensitive-endpoint-detector" {
  type dsl
  finding "sensitive_endpoint_access" when {
    request.path matches "/admin/*"
  }
  output {
    field endpoint.sensitive true
    field endpoint.sensitivity_score 30
  }
}

baseline "user-normal-login-hours" {
  entity user.id
  observe auth.login_success
  fields {
    hour timestamp.hour
  }
  window 30d
  min_samples 20
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	if bundle.Safety.MaxDetectorTimeout != 25*time.Millisecond || bundle.Safety.MaxActionTimeout != 2*time.Second || bundle.Safety.MaxRetryCount != 2 {
		t.Fatalf("safety=%#v", bundle.Safety)
	}
	if len(bundle.Detectors) != 1 || len(bundle.Detectors[0].Findings) != 1 {
		t.Fatalf("detectors=%#v", bundle.Detectors)
	}
	if bundle.Detectors[0].Findings[0].Condition != `wildcard_match(request.path, "/admin/*")` {
		t.Fatalf("condition=%q", bundle.Detectors[0].Findings[0].Condition)
	}
	if bundle.Detectors[0].Outputs["endpoint.sensitive"] != true {
		t.Fatalf("outputs=%#v", bundle.Detectors[0].Outputs)
	}
	if len(bundle.Baselines) != 1 || bundle.Baselines[0].Fields["hour"] != "timestamp.hour" {
		t.Fatalf("baselines=%#v", bundle.Baselines)
	}
}

func TestParseTCPGuardDynamicRouteMatches(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
rule "dynamic-route" {
  trigger {
    on request.received
  }
  when {
    request.path matches "/api/users/:id/order/:order_id"
  }
  risk {
    base 90
  }
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	if bundle.Rules[0].Condition != `wildcard_match(request.path, "/api/users/:id/order/:order_id")` {
		t.Fatalf("condition=%q", bundle.Rules[0].Condition)
	}
}

func TestParseTCPGuardDataSourceAndLookupBlocks(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
datasource "user-db" {
  type sql
  driver sqlite
  dsn env("USER_DB_DSN")
}

lookup "user-account-status" {
  source "user-db"
  mode function
  query "SELECT status, locked FROM users WHERE id = :user_id"
  params {
    user_id user.id
  }
  fallback {
    policy challenge
    reason "user database unavailable"
  }
}

rule "cached-ban" {
  trigger {
    on request.received
  }
  when {
    store.exists("risk-cache", concat("ban:user:", user.id)) equals true
  }
  risk {
    base 95
  }
}

policy_safety {
  max_lookup_timeout 25ms
  max_lookups_per_eval 20
  allow_datasource_types ["memory", "redis", "csv", "json", "sql", "http"]
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	if len(bundle.DataSources) != 1 || bundle.DataSources[0].ID != "user-db" || bundle.DataSources[0].Type != "sql" {
		t.Fatalf("datasources=%#v", bundle.DataSources)
	}
	if len(bundle.Lookups) != 1 || bundle.Lookups[0].Params["user_id"] != "user.id" {
		t.Fatalf("lookups=%#v", bundle.Lookups)
	}
	if bundle.Lookups[0].Fallback.Policy != tcpguard.LookupFallbackChallenge {
		t.Fatalf("fallback=%#v", bundle.Lookups[0].Fallback)
	}
	if bundle.Safety.MaxLookupsPerEval != 20 || len(bundle.Safety.AllowedDataSources) != 6 {
		t.Fatalf("safety=%#v", bundle.Safety)
	}
	if len(bundle.Rules) != 1 || !strings.Contains(bundle.Rules[0].Condition, "store_exists") {
		t.Fatalf("rules=%#v", bundle.Rules)
	}
}

func TestParseTCPGuardHardeningFields(t *testing.T) {
	bundle, err := bcl.ParseTCPGuardBundle([]byte(`
datasource "risk-api" {
  type http
  url "https://security.example.com/risk"
  method GET
  cache_ttl 5m
  cache_refresh 30s
  watch true
  allow_private_url false
}

action "notify_soc" {
  type webhook
  endpoint "https://soc.example.com/hook"
  success_codes ["2xx", "409"]
  retry_on_codes ["429", "5xx"]
  allow_private_url false
  retry {
    attempts 3
    backoff exponential
    jitter true
  }
  idempotency {
    header "Idempotency-Key"
    key concat(request.id, "-", policy.version)
  }
}
`))
	if err != nil {
		t.Fatalf("ParseTCPGuardBundle returned error: %v", err)
	}
	if len(bundle.DataSources) != 1 {
		t.Fatalf("datasources=%d want 1", len(bundle.DataSources))
	}
	ds := bundle.DataSources[0]
	if ds.CacheTTL != 5*time.Minute || ds.CacheRefresh != 30*time.Second || !ds.Watch || ds.AllowPrivateURL {
		t.Fatalf("datasource hardening fields=%#v", ds)
	}
	if len(bundle.Actions) != 1 {
		t.Fatalf("actions=%d want 1", len(bundle.Actions))
	}
	action := bundle.Actions[0]
	if len(action.SuccessCodes) != 2 || len(action.RetryOnCodes) != 2 {
		t.Fatalf("action code policies=%#v", action)
	}
	if !action.Retry.Jitter || action.Idempotency.Header != "Idempotency-Key" || action.Idempotency.Key == "" {
		t.Fatalf("action retry/idempotency=%#v", action)
	}
}

func writeTCPGuardFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
