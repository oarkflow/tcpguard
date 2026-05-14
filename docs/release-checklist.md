# TCPGuard Release Checklist

Use this checklist before shipping a production release.

## Security

- Configure management endpoints with `NewManagementServer(...)`.
- Enable at least one strong auth provider (`mTLS` and/or JWT).
- Apply route RBAC roles for `reload`, `simulate`, `explain`, `approvals`, and `audit`.
- Set CIDR allowlists for management traffic.
- Keep private outbound URLs disabled unless explicitly required.

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

## Rollout

- Validate policies with CLI (`validate`, `test`, `simulate`, `diff`).
- Roll out to canary first and verify metrics/alerts.
- Confirm reload success and audit-chain verification on canary.
- Roll out to remaining instances.
