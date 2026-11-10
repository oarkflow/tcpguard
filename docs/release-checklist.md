# TCPGuard Release Checklist

Use this checklist before shipping a production release.

## Security

- Configure management endpoints with `NewManagementServer(...)`.
- Enable at least one strong auth provider (`mTLS` and/or JWT).
- Apply route RBAC roles for `reload`, `simulate`, `explain`, `approvals`, and `audit`.
- Set CIDR allowlists for management traffic.
- Keep private outbound URLs disabled unless explicitly required.
- Configure `TrustedProxyCIDRs`; do not trust forwarded identity headers from arbitrary peers.
- Configure HTTP limits through `HTTPContextBuilder`: `MaxHeaderBytes`, `MaxHeaderCount`, `MaxURLBytes`, and `MaxBodyBytes`.
- Use `RequireHTTPS` and `AllowedHosts` for internet-facing deployments.
- Use `RequireCSRF` for cookie-authenticated browser mutations and `RequireIdempotency` for retryable business mutations.
- Enable `SecureResponseHeaders` unless the host application intentionally owns these headers.
- Use an HMAC secret provider and `policy_safety { require_signature true }` for signed machine-to-machine traffic.
- Provide real CAPTCHA/MFA/reauthentication executors; built-in actions are orchestration hooks.

## Runtime Safety

- Set `policy_safety` limits for detector, lookup, and action timeouts.
- Require approvals for destructive actions (`ban_ip`, `lock_user`, `revoke_all_sessions`).
- Configure `RetentionPolicy` (default 30 days) and capped index limits for Redis.
- Verify pagination behavior for management list endpoints in ops tooling.

## Quality Gates

- Run `go test ./...`.
- Run `go test -race ./...`.
- Run benchmark SLO check (`scripts/check_bench_slo.sh`).
- Run `govulncheck ./...`.
- Run `gosec ./...`.
- Run the full CI workflow on a clean runner; do not treat local test success as a release artifact.

## Rollout

- Validate policies with CLI (`validate`, `test`, `simulate`, `diff`).
- Roll out to canary first and verify metrics/alerts.
- Confirm reload success and audit-chain verification on canary.
- Roll out to remaining instances.

## Known dependency gate

The current `github.com/oarkflow/authz` dependency starts an audit worker before its public `ApplyConfig` call mutates engine configuration. `go test -race ./...` reports that dependency race in AuthZ integration tests. Do not publish a release with the race gate ignored; upgrade or patch the dependency before declaring the AuthZ-enabled build production-ready.
