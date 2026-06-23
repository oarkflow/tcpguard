# TCPGuard fh server example

This is a complete `github.com/oarkflow/fh` server wired to TCPGuard. It demonstrates global and endpoint-level anomaly detection, abuse handling, authz checks, signed request protection, datasource lookups, audit chain verification, incidents, approvals, management APIs, and metrics.

## Run

```bash
cd examples/tcpguard_fh_server
go mod tidy
go run .
```

Application server: `http://127.0.0.1:18184`

Management server: `http://127.0.0.1:18185`

Default management API key: `dev-management-key` or set `TCPGUARD_MGMT_API_KEY`.

## What is included

The server loads `tcpguard.bcl`, which includes rule files under `rules/*/*.bcl`.

| Area | Rules / features |
|---|---|
| Global protection | known bad IP feed, banned user cache lookup, tenant lockdown, per-IP rate limit |
| Endpoint protection | admin after-hours challenge, sensitive export challenge, dynamic user/order ownership checks |
| Abuse/anomaly detection | credential stuffing, password spray, account enumeration, ATO signals, API key sharing, UA rotation, endpoint scanning, function abuse, export abuse, destructive admin abuse, payment velocity |
| Business rules | high-value payment after-hours enforcement |
| Data lookups | CSV user directory, JSON tenant config, in-memory ban cache, SQL account status, HTTP external risk API |
| Security controls | HMAC signatures, nonce/timestamp replay checks, authz policy file, MFA/challenge/block/throttle actions |
| Enterprise operations | audit envelopes and verification, incidents, approval records, metrics snapshot, hot reload/simulate/explain management APIs |

## Curl scenarios

Clean request:

```bash
curl -i http://127.0.0.1:18184/public
```

Debug/probe query throttled by an endpoint rule:

```bash
curl -i 'http://127.0.0.1:18184/public?debug=true'
```

Global rate rule after repeated requests:

```bash
for i in 1 2 3 4 5; do curl -i -H 'X-Forwarded-For: 10.10.10.10' http://127.0.0.1:18184/public; done
```

Credential stuffing / password spray using the manual auth-failure event endpoint:

```bash
for u in a b c d; do \
  curl -i -X POST \
    -H 'X-Forwarded-For: 203.0.113.25' \
    -H "X-User-ID: $u" \
    http://127.0.0.1:18184/_demo/auth/fail; \
done
```

Account takeover signals:

```bash
curl -i -X POST \
  -H 'X-User-ID: user-1' \
  -H 'X-New-Device: true' \
  -H 'X-Previous-Country: US' \
  -H 'X-Country: NP' \
  http://127.0.0.1:18184/api/v1/account/login
```

Known banned user via memory datasource:

```bash
curl -i -H 'X-User-ID: banned-user' http://127.0.0.1:18184/public
```

Tenant lockdown via JSON datasource:

```bash
curl -i -H 'X-Tenant-ID: locked-tenant' http://127.0.0.1:18184/public
```

Bad IP via file intel feed:

```bash
curl -i -H 'X-Forwarded-For: 203.0.113.10' http://127.0.0.1:18184/public
```

Admin after-hours rule:

```bash
curl -i -X POST \
  -H 'X-User-ID: manager-1' \
  -H 'X-User-Role: admin' \
  -H 'X-Outside-Hours: true' \
  -H 'X-New-Device: true' \
  http://127.0.0.1:18184/admin/users
```

Sensitive report export:

```bash
curl -i -X POST \
  -H 'X-User-ID: manager-1' \
  -H 'X-Sensitivity: high' \
  http://127.0.0.1:18184/api/v1/reports/export
```

Repeated export abuse:

```bash
for i in 1 2 3; do \
  curl -i -X POST -H 'X-User-ID: analyst-1' http://127.0.0.1:18184/api/v1/reports/export; \
done
```

Application attack probe:

```bash
curl -i 'http://127.0.0.1:18184/public?file=../../etc/passwd'
```

Function invocation abuse:

```bash
for i in 1 2 3 4; do \
  curl -i -X POST -H 'X-User-ID: function-user' http://127.0.0.1:18184/api/v1/functions/reconcile; \
done
```

High-value payment velocity/business rule:

```bash
curl -i -X POST \
  -H 'X-User-ID: manager-1' \
  -H 'X-User-Role: finance_approver' \
  -H 'X-Business-Amount: 1500000' \
  -H 'X-Outside-Hours: true' \
  http://127.0.0.1:18184/api/v1/payments/approve
```

Dynamic route ownership check:

```bash
curl -i -X PUT \
  -H 'X-User-ID: user-1' \
  http://127.0.0.1:18184/api/users/user-2/order/order-9
```

Invalid signed transfer:

```bash
curl -i -X POST \
  -H 'X-User-ID: manager-1' \
  -H 'X-TCPGuard-Signature: bad-signature' \
  -H 'X-TCPGuard-Nonce: nonce-demo' \
  -H "X-TCPGuard-Timestamp: $(date +%s)" \
  http://127.0.0.1:18184/api/v1/transfers
```

Generate a valid transfer signature:

```bash
curl -s -X POST --data '{"amount":100}' http://127.0.0.1:18184/_demo/sign
```

Use the returned signature, nonce, and timestamp with the same body:

```bash
curl -i -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-User-ID: manager-1' \
  -H 'X-TCPGuard-Signature: <signature>' \
  -H 'X-TCPGuard-Nonce: <nonce>' \
  -H 'X-TCPGuard-Timestamp: <timestamp>' \
  --data '{"amount":100}' \
  http://127.0.0.1:18184/api/v1/transfers
```

Audit and incidents:

```bash
curl -s http://127.0.0.1:18184/_demo/audit
curl -s http://127.0.0.1:18184/_demo/incidents
curl -s http://127.0.0.1:18184/_demo/metrics
```

Management API:

```bash
curl -i -H 'X-API-Key: dev-management-key' http://127.0.0.1:18185/health
curl -i -H 'X-API-Key: dev-management-key' http://127.0.0.1:18185/audit/verify
```

## Notes

The demo uses an in-memory store for easy local execution. In production, use Redis or another shared store so abuse counters, nonce state, bans, audit state, approvals, and incident state are consistent across all application instances.
