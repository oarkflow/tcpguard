# Config API Authz Example

This example runs the runtime ConfigAPI with `github.com/oarkflow/authz` enabled.
It demonstrates:

- deny-by-default config/admin access
- RBAC roles: `config_viewer`, `config_editor`, and `config_admin`
- ACL deny overriding an editor role grant
- optimistic config versioning through `If-Match` and `X-Config-Version`
- audit events that include authz decision details
- signed bearer-token authentication that populates trusted Fiber locals

Run it:

```sh
export TCPGUARD_AUTH_SECRET="replace-with-at-least-32-random-bytes"
go run ./examples/config-api-authz
```

Run the end-to-end script. It starts the server on a temporary port, probes the
RBAC/ACL/version/audit flows, and always stops the server on success or failure:

```sh
./examples/config-api-authz/run-e2e.sh
```

Try the roles:

```sh
export TCPGUARD_AUTH_SECRET="replace-with-at-least-32-random-bytes"
VIEWER_TOKEN="$(go run ./examples/config-api-authz token viewer config_viewer)"
EDITOR_TOKEN="$(go run ./examples/config-api-authz token editor config_editor)"
ADMIN_TOKEN="$(go run ./examples/config-api-authz token admin config_admin)"

curl -i -H "Authorization: Bearer ${VIEWER_TOKEN}" \
  http://localhost:3000/api/rules

curl -i -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VIEWER_TOKEN}" \
  --data '{"name":"viewerDenied","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}' \
  http://localhost:3000/api/rules

curl -i -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${EDITOR_TOKEN}" \
  --data '{"name":"editorAllowed","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}' \
  http://localhost:3000/api/rules

curl -i -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://localhost:3000/api/authz/roles

curl -i -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://localhost:3000/demo/audit
```

Production applications should set `tcpguard.user_id`, `tcpguard.user_roles`,
`tcpguard.user_groups`, and `tcpguard.tenant_id` from trusted authentication
middleware before the ConfigAPI routes are reached. This example uses
`NewConfigAPISignedAuthMiddleware` for that trusted middleware.
