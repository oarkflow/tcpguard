# Decision Engine Contracts

This document describes the current evaluation behavior. Policy syntax and these outcomes are compatibility-sensitive; changes should be covered by fixtures and migration notes.

## Rule Matching And Ordering

- Candidate rules are filtered by event, scope, and path index, then evaluated in descending `priority` order. Rules with equal priority retain bundle order.
- Matching does not stop after the first rule. Every matching rule contributes its ID and may contribute actions.
- Distinct action references from all matching rules are deduplicated before execution.

## Risk, Severity, And Effect

- Each matched rule starts with its configured base risk, considers detector finding risks, applies risk adders, then applies the configured maximum and the engine's 100-point ceiling.
- The decision uses the risk and severity from the highest-risk matched rule. A tie keeps the earlier rule in priority order.
- In enforce mode, critical maps to block, high to challenge, medium to throttle, and lower severities to monitor. If no rule matches, `default_effect` applies.
- Monitor, shadow, and dry-run modes return monitor/allowed decisions regardless of the would-be enforcement effect.
- An approval gate can change the final decision to challenge. Action execution failures are recorded in action results and do not independently change the decision effect.

## Failure Behavior

- In enforce mode, errors in enrichment, intel, detector, derived-trigger, rule-match, risk, severity, or authorization evaluation fail closed and add a sanitized evaluation-error finding.
- In monitor, shadow, and dry-run modes, these errors are reported without blocking.
- Lookup failures follow the lookup's configured fallback. Action failures remain in `Decision.Actions`. Audit persistence failures add a sanitized finding to the returned decision without changing its effect.
- A request context may be modified during evaluation. Callers should build a fresh `Context` per request and must not evaluate the same instance concurrently.

## Runtime Bounds

`policy_safety.max_rule_eval_time` creates a per-rule deadline for condition, risk, and severity expressions. The current BCL interpreter is synchronous, so TCPGuard detects an expired deadline after a pure CPU expression returns but cannot preempt it mid-evaluation. Registered expression functions and store-backed sequence checks receive the context and should honor it. Detector, lookup, action, and authorization work use their own configured bounds; the request context deadline is the overall cancellation boundary for components that honor it.
