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

Use `go run ./cmd/tcpguard lint -dir ./policy` as a separate CI check. Warnings do not fail lint unless `-strict` is supplied.

## Lint Checklist

Run `go run ./cmd/tcpguard lint -dir ./policy` in CI. The linter reports syntax-independent authoring issues including duplicate IDs, unknown actions and datasources, missing fallbacks, broad scopes, and matching rules with different actions. Review packs for:

- broad `paths ["*"]` scopes without tenant, role, or method constraints
- destructive actions without approval
- external lookups without explicit fallback
- webhook actions without timeout and retry limits
- action references with no corresponding action definition when provider config is required
- overlapping rules that can create duplicate incidents
- unused include globs or empty policy directories

Matching rules are all evaluated; priority controls their reported order and does not short-circuit later rules. When multiple rules match, the decision risk and severity come from the highest-risk result, while distinct actions from all matching rules can run. Treat the linter's matching-rule warning as a prompt to verify that combined actions are intentional.

## Naming

Use stable IDs because they appear in decisions, audit records, metrics, and assertions. Prefer names like:

- `global-block-bad-ip`
- `admin-export-after-hours`
- `payment-high-value-approval`
- `session-impossible-travel`

## Action Integrations

Webhook-compatible actions can be used for `webhook`, `notify_admin`, `notify_user`, `notify_soc`, `siem`, and `event_bus` when an endpoint is configured.

For SQL writes or command execution, prefer a custom `ActionExecutor` registered with `WithActionExecutor`. Keep SQL parameterized and command execution allowlisted.
