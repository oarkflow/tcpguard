# TCPGuard net/http Server Example

This example runs TCPGuard with the standard library `net/http` middleware.

Run it:

```sh
go run ./examples/tcpguard_http_server
```

The server listens on `http://127.0.0.1:18182`.

Clean request:

```sh
curl -i http://127.0.0.1:18182/public \
  -H 'User-Agent: demo'
```

High-value payment block:

```sh
curl -i -X POST http://127.0.0.1:18182/payments/approve \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: manager-1' \
  -H 'X-User-Role: manager' \
  -H 'X-Tenant-ID: bank' \
  -H 'X-Business-Action: payment.approve' \
  -H 'X-Business-Amount: 1250000'
```

Admin export approval challenge:

```sh
curl -i http://127.0.0.1:18182/admin/export \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: admin-1' \
  -H 'X-User-Role: admin' \
  -H 'X-Tenant-ID: bank' \
  -H 'X-Outside-Hours: true'
```

Account takeover abuse challenge:

```sh
curl -i -X POST http://127.0.0.1:18182/account/login \
  -H 'User-Agent: demo' \
  -H 'X-User-ID: user-http' \
  -H 'X-Tenant-ID: bank' \
  -H 'X-New-Device: true' \
  -H 'X-Device-ID: device-http' \
  -H 'X-Previous-Country: US' \
  -H 'X-Country: NP'
```

Expected: HTTP `401` with matched rule `account-takeover-abuse`.

Credential stuffing / password spray. The third failed login from the same IP crosses the demo threshold:

```sh
for user in a b c; do
  curl -i -X POST http://127.0.0.1:18182/_demo/auth/fail \
    -H 'User-Agent: demo' \
    -H "X-User-ID: http-$user" \
    -H 'X-Forwarded-For: 198.51.100.88'
done
```

Expected: first two responses are allowed; the third is HTTP `403` with findings `credential_stuffing` and `password_spray`.

API key sharing across IPs:

```sh
curl -i http://127.0.0.1:18182/public \
  -H 'User-Agent: demo' \
  -H 'X-API-Key: shared-http-key' \
  -H 'X-Forwarded-For: 198.51.100.211'

curl -i http://127.0.0.1:18182/public \
  -H 'User-Agent: demo' \
  -H 'X-API-Key: shared-http-key' \
  -H 'X-Forwarded-For: 198.51.100.212'
```

Expected: the second request returns HTTP `401` with matched rule `api-key-sharing-abuse`.

Application-layer attack probes:

```sh
curl -i 'http://127.0.0.1:18182/public?q=%27%20OR%20%271%27%3D%271%20UNION%20SELECT%20password%20FROM%20users' \
  -H 'User-Agent: demo'
```

Expected: HTTP `403` with matched rule `application-attack-probe`.

Function invocation abuse. The third invocation crosses the demo threshold:

```sh
for i in 1 2 3; do
  curl -i -X POST http://127.0.0.1:18182/functions/reconcile \
    -H 'User-Agent: demo' \
    -H 'X-User-ID: function-http'
done
```

Expected: the third response is HTTP `429` with matched rule `function-invocation-abuse`.

Inspect operator endpoints:

```sh
export TCPGUARD_MGMT_API_KEY=dev-management-key
curl -s http://127.0.0.1:18182/metrics
curl -s http://127.0.0.1:18182/incidents -H "X-API-Key: $TCPGUARD_MGMT_API_KEY"
curl -s http://127.0.0.1:18182/audit/verify -H "X-API-Key: $TCPGUARD_MGMT_API_KEY"
curl -s -X POST http://127.0.0.1:18182/simulate \
  -H "X-API-Key: $TCPGUARD_MGMT_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"event":{"type":"request.received"},"context":{"request":{"id":"sim-1","path":"/public","method":"GET"}}}'
```

Run CLI validation and policy assertions:

```sh
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_http_server/policy
go run ./cmd/tcpguard test \
  -dir ./examples/tcpguard_http_server/policy \
  -request ./examples/tcpguard_http_server/request.json \
  -assert ./examples/tcpguard_http_server/assert.json
```

The example demonstrates:

- `guard.HTTPMiddleware(next)`
- custom identity and business extraction
- custom JSON response rendering
- in-memory metrics hooks
- abuse detection for account takeover, credential stuffing, API-key sharing, data export velocity, and payment velocity
- strict management endpoints (`NewManagementServer`) with auth, RBAC, body limits, and rate limiting
- policy assertion testing with the CLI
- external authz DSL integration via [`policy/tcpguard.authz`](./policy/tcpguard.authz) referenced from `guard.authz`
