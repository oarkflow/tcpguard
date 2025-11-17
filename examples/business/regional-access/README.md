# Regional Access Control

Demonstrates blocking login attempts that originate outside the banking team's approved regions.

## Highlights

- `regionalAccess.json` uses `checkBusinessRegion` to compare the resolved country against an allow/deny list.
- Endpoint config keeps standard login throttling so genuine customers are unaffected.
- Notifications flow to Slack when a region-mismatch occurs.

## Try it

```bash
PORT=3002 go run ./examples/business/regional-access
```

Override `X-Forwarded-For` when testing via curl to mimic different countries (GeoIP lookups will fall back to the provided defaults for private networks).
