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
- strict management endpoints (`NewManagementServer`) with auth, RBAC, body limits, and rate limiting
- policy assertion testing with the CLI
- external authz DSL integration via [`policy/tcpguard.authz`](./policy/tcpguard.authz) referenced from `guard.authz`
