# Business-Focused TCPGuard Examples

Each folder contains a self-contained configuration bundle under `configs/` plus a README with scenario-specific instructions.

| Folder | Scenario | Focus |
| --- | --- | --- |
| `login-hours` | Customer login after-hours lockout | Uses business-hours pipeline gates |
| `regional-access` | Geo access for support agents | Blocks non-compliant countries |
| `protected-routes` | Executive/finance APIs | Requires explicit Authorization tokens |
| `session-security` | Hijacked browsers and stolen cookies | Enforces single fingerprint per user |
| `api-surge` | Analytics export storms | Couples custom telemetry to burst controls |

## Running an example

Each folder now ships with its own tiny `main.go` that wraps the shared runner.

```bash
# from the repo root
PORT=3001 go run ./examples/business/<folder>
```

Override `PORT` if you want to deviate from the defaults (3001-3005) baked into each scenario. Point your HTTP client at the routes listed in each README to observe the actions and notifications in real time.
