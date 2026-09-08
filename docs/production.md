# TCPGuard Production Guide

Use this guide as the baseline for running TCPGuard in a multi-instance service.

## Runtime State

Use `RedisStore` when more than one process handles traffic. It shares:

- rate counters
- nonce replay state
- temporary bans and locks
- cooldowns and sequence windows
- entity risk profiles
- approvals
- incidents
- audit envelopes

Use `MemoryStore` only for tests, local demos, or single-process deployments where losing state on restart is acceptable.

## Proxy Headers

Enable `TrustedProxyHeaders` only when the service is behind trusted infrastructure that sanitizes forwarded headers.

```go
builder := tcpguard.HTTPContextBuilder{
    TrustedProxyHeaders: true,
    TrustedProxyCIDRs:   []string{"10.0.0.0/8"},
    RequireHTTPS:        true,
    AllowedHosts:        []string{"api.example.com"},
    AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
    MaxHeaderBytes:      32 << 10,
    MaxHeaderCount:      100,
    MaxURLBytes:         8 << 10,
    MaxBodyBytes:        10 << 20,
    SecureResponseHeaders: true,
    AllowedCORSOrigins: []string{"https://app.example.com"},
    CORSAllowCredentials: true,
    ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'",
}
```

If untrusted clients can set `X-Forwarded-For` or similar headers directly, leave this disabled and rely on `RemoteAddr`.

For cookie-authenticated browser APIs, also set `RequireCSRF: true`. For payment, transfer, provisioning, and other retryable mutations, set `RequireIdempotency: true`. TCPGuard atomically detects reused keys and body conflicts; the application must still persist the final response and business effect atomically in its own transaction.

## GeoIP

`HTTPContextBuilder` enriches network geography by default. Disable GeoIP in tests or in deployments that already provide network facts:

```go
builder := tcpguard.HTTPContextBuilder{DisableGeoIP: true}
```

Applications can also overwrite `sec.Network.Country`, `CountryCode`, `Region`, or related fields in a custom extractor.

## Reload Strategy

Use `ReloadableGuard` for policy reloads. It builds a new immutable guard from the candidate bundle and only publishes it when validation succeeds. If reload fails, the previous guard remains active.

Management endpoints should run behind authenticated `NewManagementServer(...)` configuration. Default posture is deny-by-default with route RBAC, request size limits, CIDR allowlists, and short read timeouts.

Recommended flow:

- Validate policy in CI with `go run ./cmd/tcpguard validate`.
- Run policy assertions with `go run ./cmd/tcpguard test -assert`.
- Diff representative fixtures before rollout.
- Reload one instance or canary first.
- Watch decision, action, detector, and reload metrics.
- Roll out to the rest of the fleet.

## Safety Defaults

Set `policy_safety` in every production pack:

```bcl
policy_safety {
  max_detector_timeout 25ms
  max_lookup_timeout 50ms
  max_action_timeout 2s
  max_actions_per_rule 8
  max_lookups_per_eval 20
  max_retry_count 2
  max_webhook_timeout 2s
  allow_datasource_types ["memory", "redis", "csv", "json", "sql", "http"]
  require_approval_for ["ban_ip", "lock_user", "revoke_all_sessions"]
}
```

Tune timeouts to preserve application latency budgets.

Also configure runtime bounds in Go for every public middleware instance:

```go
guard, err := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithRequestTimeout(2*time.Second),
    tcpguard.WithMaxConcurrentRequests(1000),
)
```

Set HTTP server `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and
`IdleTimeout` separately; TCPGuard cannot enforce socket-level slow-client
deadlines after the request reaches the handler.

## Failure Modes

For external lookups, choose fallback policy deliberately:

- `allow`: fail open and expose error facts.
- `challenge`: fail into a challenge decision.
- `block`: fail closed.
- `default`: inject known fallback values.
- `error_fact`: only expose error/found/fallback facts.

Use short timeouts for HTTP detectors, HTTP datasources, and webhooks. Treat external integrations as unreliable unless they are local and highly available.

Outbound URL hardening is enabled by default for datasource/action HTTP calls and rejects private/loopback targets unless explicitly allowed.

## Response Shaping

Use `WithResponseMessagePolicy(tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction))` or `PublicDecisionResponseRenderer` to align TCPGuard enforcement responses with safe production disclosure. Production responses include a stable request ID and readable reason while suppressing sensitive values, signatures, tokens, body payloads, datasource values, risk scores, action lists, details arrays, and internal rule details. Use `WithResponseRenderer` when the API needs a stable/custom envelope, but wrap `PublicDecisionResponseRenderer` or `PublicDecisionBody` instead of serializing raw `Decision` internals. Pair it with adapter `OnDecision` or `DecisionLogEntry` so production responses stay minimal while production logs capture the trigger, deduplicated findings, compact action summary, and correlation IDs without noisy full decision dumps.

## Observability

Use `WithMetrics` to export:

- decision counts by effect and severity
- matched rule counts
- detector latency and error counts
- action latency and failure counts
- reload success/failure counts

Bridge `MetricsRecorder` into your telemetry system for production.

## Retention And Pagination

For Redis-backed runtime state, configure `RetentionPolicy` (default 30 days) and capped indexes to keep `incidents`, `audit`, and `approvals` bounded. Use management endpoint pagination (`limit`, `cursor`, `after`, `before`) for operational reads.

## Release Checklist

Use [Release Checklist](release-checklist.md) before promoting changes to production.
