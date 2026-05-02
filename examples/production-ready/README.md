# Production-Ready Example

This example wires TCPGuard as it should be wired behind nginx or another TLS
terminating proxy:

- signed bearer authentication populating trusted Fiber locals
- `github.com/oarkflow/authz` RBAC/ABAC/ACL authorization for config/admin APIs
- SQL-backed config store with optimistic versioning
- SQL-backed state store for counters, bans, sessions, revocations, and detector state
- SQL-backed audit event storage
- CSRF protection for browser-origin config mutations
- trusted proxy CIDR handling for forwarded client IPs
- production readiness checks at startup and through `/ready`

Run it:

```sh
export TCPGUARD_AUTH_SECRET="replace-with-at-least-32-random-bytes"
export TCPGUARD_CSRF_TOKEN="replace-with-random-csrf-token"
go run ./examples/production-ready
```

Mint tokens:

```sh
VIEWER_TOKEN="$(go run ./examples/production-ready token viewer config_viewer)"
EDITOR_TOKEN="$(go run ./examples/production-ready token editor config_editor)"
ADMIN_TOKEN="$(go run ./examples/production-ready token admin config_admin)"
```

Exercise the API:

```sh
curl -i http://localhost:3000/ready
curl -i -H "Authorization: Bearer ${VIEWER_TOKEN}" http://localhost:3000/api/rules
curl -i -H "Authorization: Bearer ${ADMIN_TOKEN}" http://localhost:3000/api/audit
```

Run the end-to-end script. It starts the server on a temporary port, checks
readiness/auth/authz/CSRF/version/audit behavior, then stops the server on
success or failure:

```sh
./examples/production-ready/run-e2e.sh
```

TLS is intentionally not started by this example because the intended
deployment shape is nginx/proxy TLS termination in front of the Go process.
