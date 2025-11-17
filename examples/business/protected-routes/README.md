# Protected Routes Hardening

Blocks requests to finance/HR APIs unless the Authorization header matches one of the allow-listed service tokens.

## Components

- `protectedRoutes.json` runs `checkProtectedRoute` with wildcard routes and strict header requirements.
- `finance.json` endpoint throttles brute-force header spraying.
- Email notifications can be wired to SOC tooling via `configs/credentials.json`.

## Run it

```bash
PORT=3003 go run ./examples/business/protected-routes
```

Call `/api/finance` without the proper header to trigger the ban action.
