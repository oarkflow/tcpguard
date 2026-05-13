# TCPGuard

TCPGuard is an additive runtime security platform for Go/Fiber and `net/http` applications. It reuses the repository's `condition` expression engine and the existing `bcl` package, then adds security context, triggers, detectors, risk scoring, policy decisions, action orchestration, incidents, stores, simulation, and reload primitives.

## Public API

```go
bundle, err := bcl.LoadTCPGuardBundleDir(ctx, "./policy")
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMode(tcpguard.Enforce),
)
app.Use(guard.Middleware()) // Fiber v3
```

For `net/http`, use `guard.HTTPMiddleware(next)`.

## Performance options

Audit envelopes and entity risk profiles are enabled by default because they are part of the enterprise decision trace. For ultra-low-latency inline enforcement, disable either feature explicitly:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithMode(tcpguard.Enforce),
    tcpguard.WithoutAudit(),
    tcpguard.WithoutEntityProfiles(),
)
```

Rules, derived triggers, risk adders, severity expressions, and scoped endpoint patterns are compiled once when the guard is created or reloaded. Scoped route templates such as `/api/users/:id/order/:order_id` also expose matched parameters in `request.params`.

TCPGuard's runtime uses immutable snapshots and indexed rule candidates internally, so large packs do not require a full linear rule scan on every request. Built-in detectors are gated by request context so replay, session, business, and rate checks only run when relevant.

The fast indexed runtime is enabled by default. For parity investigations or very unusual custom rule behavior, it can be disabled without changing BCL:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithFastRuntime(false),
)
```

Rule scopes can narrow candidate selection by tenant, role, HTTP method, and endpoint path. Paths support exact matches, wildcards, prefixes, and dynamic route parameters:

```bcl
scope {
  tenants ["demo-bank"]
  roles ["admin"]
  methods ["GET", "POST"]
  paths ["/api/users/:id/order/:order_id", "/admin/*"]
}
```

Rate abuse detection defaults to the original fixed-window counter for compatibility. You can opt into more accurate algorithms:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithRateAlgorithm(tcpguard.RateSlidingWindow),
)
```

Supported algorithms are `RateFixedWindow`, `RateSlidingWindow`, and `RateTokenBucket`.

## GeoIP Country Checks

`HTTPContextBuilder` enriches `network.country`, `network.country_code`, `network.region`, `network.city`, `network.latitude`, and `network.longitude` from the client IP using `github.com/oarkflow/ip`. When `TrustedProxyHeaders` is enabled, TCPGuard uses the library's header parsing to derive the public client IP from forwarded headers.

```bcl
rule "geo-country-restriction" {
  scope {
    paths ["/geo-restricted"]
  }
  trigger {
    on request.received
  }
  when {
    all {
      network.geo_found equals true
      network.country not_equals "NP"
    }
  }
  risk {
    base 95
  }
  actions {
    critical {
      run block
      run block_country 15m
    }
  }
}
```

For tests or deployments that provide their own geo data, set `HTTPContextBuilder{DisableGeoIP: true}` or overwrite `sec.Network.Country` in an extractor.

## BCL blocks

TCPGuard BCL supports `guard`, `pack`, `datasource`, `lookup`, `rule`, `trigger`, `action`, `detector`, `enricher`, `intel`, `baseline`, `threat_model`, and `policy_safety`.

A single-file pack keeps metadata, guard config, rules, actions, intel, and threat models in one BCL file:

```bcl
pack "banking-single-file-pack" {
  version "1.0.0"
  mode enforce
}

guard "tcpguard-main" {
  mode enforce
  version "2026.05.13"
}
```

A multi-file pack can use a root BCL entrypoint with `include` globs:

```bcl
pack "banking-multi-file-pack" {
  version "1.0.0"
  mode enforce
}

guard "tcpguard-main" {
  include "./actions/*.bcl"
  include "./triggers/*.bcl"
  include "./intel/*.bcl"
  include "./rules/*/*.bcl"
}
```

Load a single file with `bcl.LoadTCPGuardBundleFile`; load a directory with `bcl.LoadTCPGuardBundleDir`.

Policies may be split across many `*.bcl` files, for example:

```txt
policy/
  00-guard.bcl
  actions/notifications.bcl
  intel/bad_ips.bcl
  triggers/business.bcl
  rules/global/bad_ip.bcl
  rules/endpoints/admin.bcl
  rules/business/high_value_payment.bcl
```

## Runtime extensions

- Datasources and lookups read memory/cache, Redis, CSV, JSON, SQL, and HTTP-backed data for rule conditions.
- Derived triggers emit new event names from existing context fields.
- DSL detectors emit findings and context fields without Go code changes.
- HTTP detectors call external scoring services with timeout and fallback.
- File intel feeds and lookup enrichers add fields to the security context.
- Baselines maintain lightweight state and expose z-score facts.
- Threat models decorate findings with STRIDE or MITRE-style categories.
- Entity profiles persist risk for user, session, device, IP, tenant, endpoint, API key, and business action.

## Rule-Facing Data Access

Rules can use external state in two ways:

- `mode preload` lookups run before detectors/rules and map fields into context facts.
- `mode function` lookups are read directly from conditions with `store.exists`, `store.value`, `store.field`, `store.found`, and `store.error`.

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

rule "locked-account" {
  trigger {
    on request.received
  }
  when {
    user.account.locked equals true
  }
  risk {
    base 80
  }
}
```

Direct function example:

```bcl
when {
  any {
    store.exists("risk-cache", concat("ban:user:", user.id)) equals true
    store.field("external-risk", "score") greater_or_equal 80
    store.error("user-account-status") not_equals ""
  }
}
```

Fallback policies are per lookup:

- `allow`: expose failure facts but do not affect the decision.
- `challenge`: force a challenge decision when the lookup fails.
- `block`: force a block decision when the lookup fails.
- `default`: use configured fallback values.
- `error_fact`: only set `store.<lookup>.error`, `found`, and `fallback_applied`.

## Safety

`policy_safety` can limit detector/action/lookup timeout, lookups per evaluation, actions per rule, retry count, webhook timeout, action allowlists, datasource type allowlists, command actions, and approval requirements for destructive responses.

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

When a matching rule has an `approval` block, TCPGuard creates an `ApprovalRecord`, suppresses that rule's actions until an allowed approver approves it, and returns a challenge decision. In enforce mode, middleware returns HTTP `401` with approval details in the response body. Rejected approvals keep the actions suppressed, retain the rejection reason, and continue to challenge.

```go
pending, _ := guard.ListApprovals(ctx, tcpguard.ApprovalPending)
approved, err := guard.Approve(ctx, pending[0].ID, "security-admin", "verified by SOC")
rejected, err := guard.Reject(ctx, pending[0].ID, "security-admin", "false positive")
```

The management server exposes `GET /approvals`, `POST /approvals/approve`, and `POST /approvals/reject`.

## Audit

Every evaluation writes an `AuditRecord` with matched rules, findings, action results, approval IDs, explanation, policy version, config hash, and a deterministic request fingerprint. Stores that implement `AuditStore` persist tamper-evident `AuditEnvelope` records.

```go
envelopes, _ := store.ListAuditEnvelopes(ctx)
err := tcpguard.VerifyAuditChain(envelopes)
```

The management server exposes `GET /audit` and `GET /audit/verify`.

## Endpoint Patterns

Path scopes and `matches` conditions support exact paths, `*` wildcards, trailing prefix wildcards, and route templates with dynamic parameters:

```bcl
paths ["/api/users/:id/order/:order_id", "/tenants/{tenant_id}/reports/*"]

when {
  request.path matches "/api/users/:id/order/:order_id"
}
```

When a scoped route template matches, route parameters are available under `request.params`, such as `request.params.id` and `request.params.order_id`.

## Stores

TCPGuard includes:

- `MemoryStore` for local/test use.
- `RedisStore` for distributed counters, cooldowns, nonces, bans, profiles, and sequence windows.

## Reload and simulation

Use `ReloadableGuard` with a bundle loader to publish immutable snapshots and keep last-known-good behavior on invalid reloads. Use `tcpguard.Simulate` for dry-run decisions.

The CLI provides initial operator commands:

```sh
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_multi_file_policy_pack
go run ./cmd/tcpguard simulate -dir ./policy -request ./request.json
go run ./cmd/tcpguard explain -dir ./policy -request ./request.json
go run ./cmd/tcpguard test -dir ./policy -request ./request.json
go run ./cmd/tcpguard diff -before-dir ./policy-old -after-dir ./policy-new -request ./request.json
```
