# TCPGuard Policy Authoring

## Pack Structure

Prefer a multi-file pack once policies grow beyond a few rules:

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

Use the root file for pack metadata, guard settings, includes, and shared safety controls.

## Rule Shape

Good rules have:

- a clear ID
- explicit status
- narrow scope
- one primary trigger
- a readable condition
- bounded risk and severity mapping
- actions only at the severity levels that need them
- approval blocks for destructive responses

## Assertions

Create a request fixture and assertion file for every critical rule. The CLI can assert:

- `effect`
- `allowed`
- `severity`
- `min_risk`
- `max_risk`
- `matched_rules`
- `findings`
- `actions`

Example:

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

Run:

```sh
go run ./cmd/tcpguard test -dir ./policy -request ./request.json -assert ./assert.json
```

## Lint Checklist

Until a first-class linter exists, review packs for:

- broad `paths ["*"]` scopes without tenant, role, or method constraints
- destructive actions without approval
- external lookups without explicit fallback
- webhook actions without timeout and retry limits
- action references with no corresponding action definition when provider config is required
- overlapping rules that can create duplicate incidents
- unused include globs or empty policy directories

## Naming

Use stable IDs because they appear in decisions, audit records, metrics, and assertions. Prefer names like:

- `global-block-bad-ip`
- `admin-export-after-hours`
- `payment-high-value-approval`
- `session-impossible-travel`

## Action Integrations

Webhook-compatible actions can be used for `webhook`, `notify_admin`, `notify_user`, `notify_soc`, `siem`, and `event_bus` when an endpoint is configured.

For SQL writes or command execution, prefer a custom `ActionExecutor` registered with `WithActionExecutor`. Keep SQL parameterized and command execution allowlisted.
