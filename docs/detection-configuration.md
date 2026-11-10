# Configuration-Driven Detection

TCPGuard's built-in detectors can evaluate HTTP requests and application events. For business events, the host application still needs to pass facts it already knows (such as the authenticated identity, transaction ID, amount, approval count, and event type) to `Guard.Evaluate`; TCPGuard does not infer those values from an opaque request body.

Policies and detector paths can read `context.user.id`, `request.path`, `request.query.payment_id`, `request.params.order_id`, and headers through either `header.x-api-key`, `request.header.x-api-key`, or `request.headers.x-api-key`. Header lookups are case-insensitive. Query and route parameter maps are exposed as traversable facts.

## Business and Cross-Service Controls

Configure temporal and domain thresholds in a `business_anomaly` detector:

```bcl
detector "business-controls" {
  type business_anomaly
  window 15m
  authz_failure_threshold 5
  body_size_threshold 10485760
  duration_threshold_ms 30000
  high_value_threshold 1000000
  approval_amount_threshold 100000
  refund_amount_threshold 50000
  payout_amount_threshold 250000
  service_allowlist ["billing-worker", "payments-api"]
  privileged_roles ["admin", "owner", "super_admin"]
}
```

The detector reports authorization failure velocity, oversized or slow requests, role elevation, cross-user permission changes, unknown service identities, approval gaps, duplicate transactions, large refunds/payouts, and refund/payout velocity. `service_allowlist` checks `identity.id` for identities whose `identity.type` is `service` or `workload`.

For event-based checks, send a typed `Event` with fields such as:

- `authz.denied`: `status` or a denial event type, plus actor identity in the context.
- `security.privilege_changed`: `old_role`, `new_role`, or `privilege_escalation`; cross-user permission changes can include `actor_user_id` and `target_user_id`.
- `business.approval`: `approval_required`, `approval_count`, plus `business.approval_level` in context.
- Payment-like events: `transaction_id` (or `payment_id`) and a `business.action`/workflow/entity containing `payment`, `transfer`, `payout`, or `refund`.
- Resource checks: `duration_ms` in event fields and request body size in context.

Use ordinary BCL rules to choose the response for emitted findings: challenge, block, throttle, open an incident, or notify an operator. Detector findings provide signals; the policy determines enforcement.

## Tenant-Specific Behavioral Baselines

Define a baseline per entity and observation event. The configured entity can be `tenant.id`, `user.id`, or another fact path; the fields map aliases to numeric facts. TCPGuard learns per-entity means and variance and reports deviations after `min_samples` observations. Baseline updates are atomic when the configured store implements `AtomicUpdater` (the built-in memory, Redis, and SQLite stores do).

```bcl
baseline "tenant-payment-amount" {
  entity tenant.id
  observe business.payment
  window 30d
  min_samples 30
  fields {
    amount business.amount
  }
}
```

Applications must supply consistent facts and event names across requests. Configure a shared store such as Redis for multi-instance deployments so counters and baselines cover the fleet.
