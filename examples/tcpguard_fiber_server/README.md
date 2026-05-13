# TCPGuard Fiber Server Example

This example runs Fiber v3 with `guard.Middleware()` and a TCPGuard BCL pack that demonstrates:

- allow responses with `X-TCPGuard-Risk`
- structured enforcement errors
- per-IP throttling with HTTP `429`
- bad-IP intel blocking with HTTP `403`
- HMAC/signature and nonce replay blocking
- dynamic route parameters such as `/api/users/:id/order/:order_id`
- derived business triggers
- DSL detectors
- CSV lookup enrichment
- approval, rejection, incidents, and tamper-evident audit envelopes
- rule-facing datasource lookups for memory/cache, CSV, JSON, HTTP, and SQLite
- GeoIP country lookup through `github.com/oarkflow/ip`

Run it:

```sh
go run ./examples/tcpguard_fiber_server
```

The root `tcpguard.bcl` keeps shared pack configuration, datasources, lookups, actions, intel, detectors, baselines, and triggers. Endpoint/business/security rules live in separate files under `rules/` and are loaded through:

```bcl
include "./rules/*/*.bcl"
```

On startup, the server prints aligned tables showing the loaded bundle metadata, datasources, lookups, and rule inventory with priority, status, triggers, paths, actions, and approval requirements.

The server listens on `http://127.0.0.1:18181`. Keep it running in one terminal and run the checks below from another terminal. Stop it with `Ctrl-C`.

## Quick Verification

Clean request:

```sh
curl -i http://127.0.0.1:18181/public \
  -H 'User-Agent: demo'
```

Expected: HTTP `200`, `X-TCPGuard-Risk: 0`, and JSON with `"ok": true`.

Bad IP from file intel:

```sh
curl -i http://127.0.0.1:18181/public \
  -H 'User-Agent: demo' \
  -H 'X-Forwarded-For: 203.0.113.42'
```

Expected: HTTP `403`, `effect/error` of `block`, matched rule `block-bad-ip`, and an incident action.

Rate limit. The fourth request from the same IP returns HTTP `429`:

```sh
for i in 1 2 3 4; do
  curl -i http://127.0.0.1:18181/public \
    -H 'User-Agent: demo' \
    -H 'X-Forwarded-For: 192.0.2.44'
done
```

Expected: the final response is HTTP `429`, `effect/error` of `throttle`, matched rule `demo-rate-limit`, and `rate.ip.requests` above `3`.

DSL detector throttle:

```sh
curl -i 'http://127.0.0.1:18181/public?debug=true' \
  -H 'User-Agent: demo'
```

Expected: HTTP `429` with finding `debug_query_probe`.

Memory/cache datasource ban:

```sh
curl -i http://127.0.0.1:18181/public \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: banned-user'
```

Expected: HTTP `403` with matched rule `cache-banned-user`.

JSON tenant config datasource:

```sh
curl -i http://127.0.0.1:18181/public \
  -H 'User-Agent: demo' \
  -H 'X-Tenant-ID: locked-bank'
```

Expected: HTTP `403` with matched rule `tenant-lockdown`.

Country restriction through GeoIP:

```sh
curl -i http://127.0.0.1:18181/geo-restricted \
  -H 'User-Agent: demo' \
  -H 'X-Forwarded-For: 8.8.8.8'
```

Expected: HTTP `403` with matched rule `geo-country-restriction` because the endpoint only allows Nepal (`NP`) IPs.

Allowed Nepal IP:

```sh
curl -i http://127.0.0.1:18181/geo-restricted \
  -H 'User-Agent: demo' \
  -H 'X-Forwarded-For: 27.34.68.218'
```

Expected: HTTP `200` because TCPGuard maps the IP to `network.country == "NP"`.

SQLite account-status datasource:

```sh
curl -i http://127.0.0.1:18181/public \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: locked-user'
```

Expected: HTTP `401` with matched rule `locked-account`.

HTTP risk datasource:

```sh
curl -i http://127.0.0.1:18181/public \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: risky-http'
```

Expected: HTTP `401` with matched rule `external-risk-score`.

Admin after-hours request with an approval record. The rule suppresses its configured response actions until an allowed approver approves it and returns HTTP `401` challenge while approval is pending:

```sh
curl -i -X POST http://127.0.0.1:18181/admin/users \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: manager-1' \
  -H 'X-User-Role: admin' \
  -H 'X-Outside-Hours: true' \
  -H 'X-New-Device: true'

curl -s http://127.0.0.1:18181/_demo/approvals?status=pending
```

Expected: HTTP `401`, `effect/error` of `challenge`, `X-TCPGuard-Risk` above `0`, and an `approvals` array in the response. The approval query returns a `pending` record with rule `admin-after-hours-department-check`.

Approve or reject a pending approval:

```sh
APPROVAL_ID="<id from /_demo/approvals>"

curl -i -X POST "http://127.0.0.1:18181/_demo/approvals/$APPROVAL_ID/approve" \
  -H 'X-Approver: security-admin' \
  -H 'X-Reason: verified by SOC'

curl -i -X POST "http://127.0.0.1:18181/_demo/approvals/$APPROVAL_ID/reject" \
  -H 'X-Approver: security-admin' \
  -H 'X-Reason: false positive'
```

Dynamic endpoint parameters:

```sh
curl -i -X PUT http://127.0.0.1:18181/api/users/user-2/order/order-9 \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: user-1' \
  -H 'X-User-Role: member'
```

Expected: HTTP `401` challenge with matched rule `dynamic-order-change`; TCPGuard extracts `request.params.id` and `request.params.order_id` from the route template.

Derived high-value payment trigger:

```sh
curl -i -X POST http://127.0.0.1:18181/api/v1/payments/approve \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: manager-1' \
  -H 'X-User-Role: manager' \
  -H 'X-Business-Action: payment.approve' \
  -H 'X-Business-Amount: 1250000' \
  -H 'X-Outside-Hours: true'
```

Expected: HTTP `403`, matched rule `high-value-payment-after-hours`, and incident/SOC actions.

Invalid signed transfer:

```sh
curl -i -X POST http://127.0.0.1:18181/api/v1/transfers \
  -H 'User-Agent: demo' \
  -H 'X-TCPGuard-Signature: bad' \
  -H 'X-TCPGuard-Nonce: replay-me' \
  -H "X-TCPGuard-Timestamp: $(date +%s)" \
  -d '{"amount":100}'
```

Expected: HTTP `403`, matched rule `signed-transfer-replay-or-mitm`, and findings such as `invalid_signature`.

Valid signed transfer, then nonce replay. First request is allowed; the second is blocked:

```sh
curl -s -X POST 'http://127.0.0.1:18181/_demo/sign?method=POST&path=/api/v1/transfers' \
  -H 'Content-Type: application/json' \
  -d '{"amount":100}'
```

Use the returned `signature`, `nonce`, and `timestamp`:

```sh
curl -i -X POST http://127.0.0.1:18181/api/v1/transfers \
  -H 'User-Agent: demo' \
  -H 'Content-Type: application/json' \
  -H 'X-TCPGuard-Signature: <signature>' \
  -H 'X-TCPGuard-Nonce: <nonce>' \
  -H 'X-TCPGuard-Timestamp: <timestamp>' \
  -d '{"amount":100}'
```

Expected: the first request is HTTP `200`. Repeat the exact same request with the same nonce; the replay is HTTP `403` with finding `nonce_reused`.

Inspect operator data:

```sh
curl -s http://127.0.0.1:18181/_demo/incidents
curl -s http://127.0.0.1:18181/_demo/audit
```

Expected: incidents are JSON records from `create_incident`; audit returns `{"valid":true,...}` when the tamper-evident chain verifies.
