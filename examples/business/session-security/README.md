# Session Security

Enforces single-user fingerprint consistency to catch hijacked browser sessions.

- The pipeline leverages the built-in `checkSessionHijacking` node with a 12h timeout window.
- Endpoints throttle refresh storms and optionally ban suspicious fingerprints.
- Notifications can flow to a webhook for SOC enrichment.

## Run the scenario

```bash
PORT=3004 go run ./examples/business/session-security
```

Send repeated requests with different `User-Agent` or `X-User-ID` headers to see the session monitor trigger.
