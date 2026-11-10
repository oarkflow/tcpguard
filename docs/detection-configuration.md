# Configuration-Driven Detection

TCPGuard's built-in detectors can evaluate HTTP requests and application events. For business events, the host application still needs to pass facts it already knows (such as the authenticated identity, transaction ID, amount, approval count, and event type) to `Guard.Evaluate`; TCPGuard does not infer those values from an opaque request body. HTTP abuse probes scan paths, query values, event fields, and text, JSON, XML, or form request bodies up to 1 MiB; binary bodies are skipped, and the request stream is restored for the application.

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
  sensitive_record_threshold 100
  service_allowlist ["billing-worker", "payments-api"]
  privileged_roles ["admin", "owner", "super_admin"]
}
```

The detector reports authorization failure velocity, oversized or slow requests, role elevation, cross-user permission changes, unknown service identities, approval gaps, duplicate transactions, large refunds/payouts, and refund/payout velocity. `service_allowlist` checks `identity.id` for identities whose `identity.type` is `service` or `workload`.

It also detects bulk access to sensitive records and high record-access velocity for an actor or tenant. Emit an event such as `security.data_access` after the application has authorized and completed a read, and include `sensitive: true` (or `sensitivity: "high"`) and `records_count`. The default threshold is 100 records per operation or per configured window; set `sensitive_record_threshold` to tune it. The application should report the number of records returned because TCPGuard does not inspect response bodies. This works with any server adapter that passes the event to `Guard.Evaluate`.

For event-based checks, send a typed `Event` with fields such as:

- `authz.denied`: `status` or a denial event type, plus actor identity in the context.
- `security.privilege_changed`: `old_role`, `new_role`, or `privilege_escalation`; cross-user permission changes can include `actor_user_id` and `target_user_id`.
- `business.approval`: `approval_required`, `approval_count`, plus `business.approval_level` in context.
- Payment-like events: `transaction_id` (or `payment_id`) and a `business.action`/workflow/entity containing `payment`, `transfer`, `payout`, or `refund`.
- Resource checks: `duration_ms` in event fields and request body size in context.

## Breach and Compromise Events

The built-in security breach detector converts confirmed incident events such as `security.data_breach`, `security.credential_exposure`, and `security.server_compromise` into critical findings. A suspected event such as `security.breach_suspected` produces a separate high-risk finding. Send these events from the application, SIEM, cloud security service, or other trusted telemetry source; TCPGuard cannot confirm a breach from an opaque request alone. The detector records only the event type and classification, so do not put exposed secrets or raw sensitive values in event fields.

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
