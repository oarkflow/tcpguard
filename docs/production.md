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
}
```

If untrusted clients can set `X-Forwarded-For` or similar headers directly, leave this disabled and rely on `RemoteAddr`.

## GeoIP

`HTTPContextBuilder` enriches network geography by default. Disable GeoIP in tests or in deployments that already provide network facts:

```go
builder := tcpguard.HTTPContextBuilder{DisableGeoIP: true}
```

Applications can also overwrite `sec.Network.Country`, `CountryCode`, `Region`, or related fields in a custom extractor.

## Reload Strategy

Use `ReloadableGuard` for policy reloads. It builds a new immutable guard from the candidate bundle and only publishes it when validation succeeds. If reload fails, the previous guard remains active.

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

## Failure Modes

For external lookups, choose fallback policy deliberately:

- `allow`: fail open and expose error facts.
- `challenge`: fail into a challenge decision.
- `block`: fail closed.
- `default`: inject known fallback values.
- `error_fact`: only expose error/found/fallback facts.

Use short timeouts for HTTP detectors, HTTP datasources, and webhooks. Treat external integrations as unreliable unless they are local and highly available.

## Response Shaping

Use `WithResponseRenderer` to align TCPGuard enforcement responses with the API's standard error envelope. Include a stable request ID and avoid exposing sensitive rule internals to public clients.

## Observability

Use `WithMetrics` to export:

- decision counts by effect and severity
- matched rule counts
- detector latency and error counts
- action latency and failure counts
- reload success/failure counts

Bridge `MetricsRecorder` into your telemetry system for production.
