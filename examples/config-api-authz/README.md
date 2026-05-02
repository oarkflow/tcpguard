# Config API Authz Example

This example runs the runtime ConfigAPI with `github.com/oarkflow/authz` enabled.
It demonstrates:

- deny-by-default config/admin access
- RBAC roles: `config_viewer`, `config_editor`, and `config_admin`
- ACL deny overriding an editor role grant
- optimistic config versioning through `If-Match` and `X-Config-Version`
- audit events that include authz decision details

Run it:

```sh
go run ./examples/config-api-authz
```

Run the end-to-end script. It starts the server on a temporary port, probes the
RBAC/ACL/version/audit flows, and always stops the server on success or failure:

```sh
./examples/config-api-authz/run-e2e.sh
```

Try the roles:

```sh
curl -i -H "X-Demo-User: viewer" -H "X-Demo-Roles: config_viewer" \
  http://localhost:3000/api/rules

curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Demo-User: viewer" -H "X-Demo-Roles: config_viewer" \
  --data '{"name":"viewerDenied","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}' \
  http://localhost:3000/api/rules

curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Demo-User: editor" -H "X-Demo-Roles: config_editor" \
  --data '{"name":"editorAllowed","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}' \
  http://localhost:3000/api/rules

curl -i -H "X-Demo-User: admin" -H "X-Demo-Roles: config_admin" \
  http://localhost:3000/api/authz/roles

curl -i http://localhost:3000/demo/audit
```

`X-Demo-*` headers are intentionally demo-only. Production applications should set
`tcpguard.user_id`, `tcpguard.user_roles`, `tcpguard.user_groups`, and
`tcpguard.tenant_id` from trusted authentication middleware before the ConfigAPI
routes are reached.
