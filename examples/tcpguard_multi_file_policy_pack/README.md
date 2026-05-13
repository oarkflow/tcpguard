# TCPGuard Multi-File Policy Pack

This example demonstrates loading a complete TCPGuard policy pack from a directory of BCL files. It also proves the root `00-guard.bcl` can act as a multi-file `pack` entrypoint with `include` globs:

```sh
go run ./examples/tcpguard_multi_file_policy_pack
```

CLI validation, simulation, explanation, and package testing can use the included `request.json` fixture:

```sh
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_multi_file_policy_pack
go run ./cmd/tcpguard simulate -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard explain -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard test -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
```

Layout:

```txt
00-guard.bcl
request.json
actions/notifications.bcl
intel/bad_ips.bcl
intel/bad_ips.txt
triggers/business.bcl
rules/global/bad_ip.bcl
rules/endpoints/admin.bcl
rules/endpoints/export.bcl
rules/endpoints/orders.bcl
rules/business/high_value_payment.bcl
rules/session/impossible_travel.bcl
```

The root file contains both pack metadata and includes:

```bcl
pack "banking-multi-file-pack" {
  version "1.0.0"
  mode enforce
}

guard "tcpguard-multi-file-pack" {
  mode enforce
  version "2026.05.13"

  include "./actions/*.bcl"
  include "./triggers/*.bcl"
  include "./intel/*.bcl"
  include "./rules/*/*.bcl"
}
```

The companion single-file example at `examples/tcpguard_banking_protection_pack/tcpguard.bcl` uses the same `pack` block but keeps all rules, actions, intel, and threat models in one file.

The example proves:

- Global rules can live separately from endpoint rules.
- Endpoint rules can be grouped by API surface.
- Endpoint rules can use route templates such as `/api/users/:id/order/:order_id`.
- Business rules can use derived triggers.
- Session rules can use auth/session events.
- Action definitions can be shared across files.
- Threat intel files resolve relative to the `.bcl` file that references them.
- Rules with `approval` blocks create pending approval records before destructive actions run.

Dynamic route parameters are available in BCL as request params:

```bcl
scope {
  paths ["/api/users/:id/order/:order_id"]
}

when {
  all {
    request.path matches "/api/users/:id/order/:order_id"
    request.params.id not_equals ""
    request.params.order_id not_equals ""
  }
}
```

Approval-gated actions are declared in BCL:

```bcl
approval {
  required true
  approvers ["security-admin", "platform-owner"]
}
```
