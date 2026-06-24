# TCPGuard Usage Guide

This guide covers the practical path from installing TCPGuard to running policy packs in a Go service.

## Installation

Add the module to a Go project:

```sh
go get github.com/oarkflow/tcpguard
```

Typical imports:

```go
import (
    "github.com/oarkflow/tcpguard"
    "github.com/oarkflow/tcpguard/bcl"
)
```

The core module depends only on Go's `net/http` request model. Frameworks that
do not expose `http.Handler` can call `guard.EvaluateHTTPRequest(request)` and
use the returned decision and response, or use an optional adapter.

## Loading Policies

Load a single BCL file:

```go
bundle, err := bcl.LoadTCPGuardBundleFile(ctx, "./policy/tcpguard.bcl")
```

Load a directory of BCL files:

```go
bundle, err := bcl.LoadTCPGuardBundleDir(ctx, "./policy")
```

A directory pack normally has one root file with pack metadata and include globs:

```bcl
pack "banking-multi-file-pack" {
  version "1.0.0"
  mode enforce
}

guard "tcpguard-main" {
  mode enforce
  version "2026.05.13"

  include "./actions/*.bcl"
  include "./triggers/*.bcl"
  include "./intel/*.bcl"
  include "./rules/*/*.bcl"
}
```

TCPGuard supports `guard`, `pack`, `datasource`, `lookup`, `rule`, `trigger`, `action`, `detector`, `enricher`, `intel`, `baseline`, `threat_model`, and `policy_safety` blocks.

## Fiber Middleware

```go
import tcpguardfiber "github.com/oarkflow/tcpguard/adapters/fiber"

bundle, err := bcl.LoadTCPGuardBundleDir(ctx, "./policy")
if err != nil {
    return err
}

guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMode(tcpguard.Enforce),
)
if err != nil {
    return err
}

app.Use(tcpguardfiber.Middleware(guard))
```

The Fiber example in `examples/tcpguard_fiber_server` shows identity extraction, business context extraction, policy inventory output, demo management endpoints, and end-to-end curl checks.

To authorize every request through an `oarkflow/authz` DSL file, configure:

```bcl
authz {
  file "./access.authz"
  enforce_http true
  timeout 25ms
  error_policy deny
}
```

TCPGuard loads the file through AuthZ's parser and engine, including policies,
roles, inherited roles, ACLs, memberships, tenants, hierarchy, and engine cache
settings. Extracted identity IDs are not rewritten; keep them consistent with
the IDs used by `members` and ACL subjects.

## net/http Middleware

```go
bundle, err := bcl.LoadTCPGuardBundleDir(ctx, "./policy")
if err != nil {
    return err
}

guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMode(tcpguard.Enforce),
)
if err != nil {
    return err
}

next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
})

protected := guard.HTTPMiddleware(next)
log.Fatal(http.ListenAndServe(":8080", protected))
```

See `examples/tcpguard_http_server` for a runnable `net/http` app with custom context extraction, custom rejection responses, metrics, management endpoints, and CLI policy assertions.

Use `HTTPContextBuilder` when you need to customize request context extraction:

```go
builder := tcpguard.HTTPContextBuilder{
    TrustedProxyHeaders: true,
    IdentityExtractor: func(r *http.Request, sec *tcpguard.Context) {
        sec.Identity.ID = r.Header.Get("X-User-ID")
        sec.Identity.Role = r.Header.Get("X-User-Role")
        sec.Tenant.ID = r.Header.Get("X-Tenant-ID")
    },
}

guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithContextBuilder(builder),
)
```

Set `DisableGeoIP: true` for tests or deployments that provide their own network geography facts.

## Modes

TCPGuard supports these runtime modes:

- `Monitor`: observe and score without inline enforcement.
- `Shadow`: evaluate candidate policy behavior without enforcing it.
- `DryRun`: simulation-oriented evaluation.
- `Enforce`: enforce challenge, throttle, block, revoke, and escalation decisions.

Policy packs can set mode in BCL, and Go options can set it with `tcpguard.WithMode`.

## Stores

TCPGuard includes:

- `MemoryStore` for local development, tests, single-process counters, approvals, incidents, and audit envelopes.
- `RedisStore` for distributed keys such as counters, cooldowns, nonces, bans, profiles, and approval records.

Example:

```go
store := tcpguard.NewMemoryStore()

guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithStore(store),
)
```

Use Redis when multiple service instances must share rate counters, nonces, bans, or other enforcement state.

`RedisStore` also implements approval, incident, and audit-envelope persistence, so it can be used as the shared backing store for management endpoints in multi-instance deployments.

## Custom Responses

Use `WithResponseRenderer` to shape enforced middleware responses without forking TCPGuard. The renderer can set status, headers, and body. If status or body is omitted, TCPGuard falls back to the default status mapping and JSON response.

For most APIs prefer `WithResponseMessagePolicy` or `PublicDecisionResponseRenderer` instead of hand-writing the whole renderer. This keeps denied/challenged/throttled responses understandable while making detail disclosure environment-aware:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithResponseMessagePolicy(tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction)),
)
```

Production responses include a stable `code`, readable `message`, safe `reason`, `status`, and `request_id`. They intentionally omit duplicated outcome fields, risk scores, action lists, evidence, rule internals, and details arrays. Development/test responses can include matched rule IDs, finding messages, evidence, actions, and non-sensitive values. Sensitive fields such as authorization, cookies, tokens, signatures, nonces, API keys, passwords, cards, and payload/body fields are redacted.


```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMode(tcpguard.Enforce),
    tcpguard.WithResponseRenderer(func(sec *tcpguard.Context, decision tcpguard.Decision) tcpguard.DecisionResponse {
        return tcpguard.DecisionResponse{
            Status:  http.StatusForbidden,
            Headers: map[string]string{"X-TCPGuard-Risk": fmt.Sprintf("%.0f", decision.Risk.Score)},
            Body: map[string]any{
                "error":      "request_rejected",
                "request_id": sec.Request.ID,
                "effect":     decision.Effect,
            },
        }
    }),
)
```

## Metrics

Use `WithMetrics` to record decision, detector, action, and reload events. `NewMemoryMetrics` is included for tests, examples, and local inspection.

```go
metrics := tcpguard.NewMemoryMetrics()

guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMetrics(metrics),
)

snapshot := metrics.Snapshot()
```

For production, implement `MetricsRecorder` and bridge the callbacks into OpenTelemetry, Prometheus, StatsD, or another telemetry pipeline.

## Datasources And Lookups

Rules can read external state through preload lookups or function lookups.

Preload lookup:

```bcl
datasource "user-db" {
  type sql
  driver sqlite
  dsn env("USER_DB_DSN")
}

lookup "user-account-status" {
  source "user-db"
  mode preload
  query "SELECT status, locked FROM accounts WHERE id = :user_id"
  params {
    user_id user.id
  }
  output {
    map "status" to user.account.status
    map "locked" to user.account.locked
  }
  fallback {
    policy challenge
    reason "account database unavailable"
  }
}
```

Function lookup inside a rule condition:

```bcl
when {
  any {
    store.exists("risk-cache", concat("ban:user:", user.id)) equals true
    store.field("external-risk", "score") greater_or_equal 80
    store.error("user-account-status") not_equals ""
  }
}
```

Lookup fallback policies are `allow`, `challenge`, `block`, `default`, and `error_fact`.

## Endpoint Patterns

Path scopes and `matches` conditions support exact paths, wildcards, trailing prefix wildcards, and route templates:

```bcl
scope {
  paths ["/api/users/:id/order/:order_id", "/tenants/{tenant_id}/reports/*"]
}

when {
  request.path matches "/api/users/:id/order/:order_id"
}
```

When a scoped route template matches, route parameters are available under `request.params`, such as `request.params.id` and `request.params.order_id`.

## Performance Options

Audit envelopes and entity risk profiles are enabled by default. Disable them for very low-latency inline paths when that trace data is not needed:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMode(tcpguard.Enforce),
    tcpguard.WithoutAudit(),
    tcpguard.WithoutEntityProfiles(),
)
```

The indexed runtime is enabled by default. Disable it only for parity investigations:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithFastRuntime(false),
)
```

Rate abuse detection supports fixed-window, sliding-window, and token-bucket algorithms:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithRateAlgorithm(tcpguard.RateSlidingWindow),
)
```

## Safety Controls

`policy_safety` can restrict detector, lookup, action, and webhook timeouts; max actions per rule; max lookups per evaluation; retry counts; allowed action types; allowed datasource types; command actions; and approval requirements for destructive responses.

```bcl
policy_safety {
  max_detector_timeout 25ms
  max_lookup_timeout 25ms
  max_action_timeout 2s
  max_actions_per_rule 10
  max_lookups_per_eval 20
  max_retry_count 3
  allow_datasource_types ["memory", "redis", "csv", "json", "sql", "http"]
  require_approval_for ["block", "ban_ip", "lock_user"]
}
```

## Approvals

Rules with an `approval` block create pending approval records before destructive actions run. Pending approvals suppress that rule's response actions and return a challenge decision.

```bcl
approval {
  required true
  approvers ["security-admin", "platform-owner"]
}
```

Go API:

```go
pending, _ := guard.ListApprovals(ctx, tcpguard.ApprovalPending)
approved, err := guard.Approve(ctx, pending[0].ID, "security-admin", "verified by SOC")
rejected, err := guard.Reject(ctx, pending[0].ID, "security-admin", "false positive")
```

## Audit

Every evaluation writes an `AuditRecord` with decision, risk, severity, matched rules, findings, evidence, action results, approval IDs, explanation, policy version, config hash, and request fingerprint. Stores that implement `AuditStore` persist tamper-evident audit envelopes.

```go
envelopes, _ := store.ListAuditEnvelopes(ctx)
err := tcpguard.VerifyAuditChain(envelopes)
```

## Reloads And Simulation

Use `ReloadableGuard` to publish immutable policy snapshots while preserving last-known-good behavior if a reload fails.

```go
reloadable, err := tcpguard.NewReloadableGuard(
    ctx,
    "./policy",
    bcl.LoadTCPGuardBundleDir,
    tcpguard.WithMode(tcpguard.Enforce),
)
```

Use `tcpguard.Simulate` and `tcpguard.DiffSimulations` to evaluate policies without enforcing them.

## Management Server

Use `NewManagementServer(...)` with explicit auth and route authorization. Unsecured management server wiring is rejected by default.

```go
management := tcpguard.NewManagementServer(reloadable, tcpguard.ManagementServerConfig{
    AuthProvider: tcpguard.StaticAPIKeyAuth{
        Keys: map[string]tcpguard.ManagementPrincipal{
            os.Getenv("TCPGUARD_MGMT_API_KEY"): {Subject: "ops", Roles: []string{"admin"}},
        },
    },
    Authorizer: tcpguard.RoleBasedAuthorizer{
        RolesByRoute: map[tcpguard.ManagementRoute][]string{
            tcpguard.ManagementRouteHealth:   {"admin"},
            tcpguard.ManagementRouteReload:   {"admin"},
            tcpguard.ManagementRouteSimulate: {"admin", "analyst"},
            tcpguard.ManagementRouteExplain:  {"admin", "analyst"},
            tcpguard.ManagementRouteAudit:    {"admin", "auditor"},
            tcpguard.ManagementRouteApprovals: {"admin", "approver"},
        },
    },
    AllowedCIDRs: []string{"127.0.0.0/8"},
    MaxBodyByRoute: map[tcpguard.ManagementRoute]int64{
        tcpguard.ManagementRouteSimulate: 1 << 20,
        tcpguard.ManagementRouteExplain:  1 << 20,
    },
    ReadTimeout:     2 * time.Second,
    PerIPRateLimit:  120,
    RateLimitWindow: time.Minute,
})
```

Management routes exposed by `ManagementServer`:

- `GET /health`: readiness check.
- `POST /reload`: reload policy from the configured source.
- `POST /simulate`: evaluate a simulation request.
- `POST /explain`: evaluate and return explanation-oriented output.
- `GET /incidents`: list incidents when the store supports them.
- `GET /audit`: list audit envelopes when the store supports them.
- `GET /audit/verify`: verify the audit envelope chain.
- `GET /approvals`: list approvals, optionally filtered by `status`.
- `POST /approvals/approve`: approve a pending approval.
- `POST /approvals/reject`: reject a pending approval.

List endpoints (`/incidents`, `/audit`, `/approvals`) support `limit`, `cursor`, `after`, and `before` query parameters.

## CLI

The CLI lives at `cmd/tcpguard`:

```sh
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_multi_file_policy_pack
go run ./cmd/tcpguard simulate -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard explain -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard test -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard test -dir ./examples/tcpguard_http_server/policy -request ./examples/tcpguard_http_server/request.json -assert ./examples/tcpguard_http_server/assert.json
go run ./cmd/tcpguard diff -before-dir ./policy-old -after-dir ./policy-new -request ./request.json
go run ./cmd/tcpguard reload -dir ./examples/tcpguard_multi_file_policy_pack
```

Command summary:

- `validate`: load and compile a policy pack.
- `simulate`: run one simulation request.
- `explain`: run one simulation and emit explanation output.
- `diff`: compare decisions between two policy packs.
- `test`: validate a pack, optionally evaluate a request fixture, and optionally enforce a JSON assertion file.
- `reload`: validate that a policy pack can be loaded into a new guard.

Assertion files can check the expected decision shape:

```json
{
  "effect": "block",
  "allowed": false,
  "severity": "critical",
  "min_risk": 90,
  "matched_rules": ["high-value-payment"],
  "actions": ["block", "create_incident"]
}
```

## Safe public responses plus detailed operator logs

For production APIs, do not serialize the raw `Decision` directly to users. Use `WithResponseMessagePolicy` and `PublicDecisionResponseRenderer` to produce a minimal, understandable, non-sensitive response. Keep `WithResponseRenderer` when your API needs a custom envelope; the renderer should wrap the public renderer, not expose raw findings/evidence fields.

For debugging, audit, SOC, or SIEM pipelines, use `DecisionLogEntry`. The production default is compact and debuggable: it logs triggered rules, the top reason, deduplicated findings, compact action summary, request ID, method/path, safe entity references, policy version, incident reference, and audit ID. It avoids dumping full traces, audit hashes, all request headers, business context, and repeated rate-counter evidence into normal logs. Use `policy.LogLevel = tcpguard.DecisionLogFull` or `TCPGUARD_ENV=development` when a full redacted diagnostic entry is needed.

```go
policy := tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction)

guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithResponseMessagePolicy(policy),
    tcpguard.WithResponseRenderer(func(sec *tcpguard.Context, d tcpguard.Decision) tcpguard.DecisionResponse {
        return tcpguard.PublicDecisionResponseRenderer(policy)(sec, d)
    }),
)

entry := tcpguard.DecisionLogEntry(sec, decision, policy)
// log entry using your logger/SIEM pipeline
_ = entry
```
