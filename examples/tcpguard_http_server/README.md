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
curl -s http://127.0.0.1:18182/metrics
curl -s http://127.0.0.1:18182/incidents
curl -s http://127.0.0.1:18182/audit/verify
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
- management endpoints
- policy assertion testing with the CLI
