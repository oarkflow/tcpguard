# Action Templates

This directory contains standalone JSON snippets for every built-in mitigation action supported by TCPGuard:

- `rate_limit.json` – throttles requests and sets `Retry-After` headers.
- `temporary_ban.json` – short-lived bans with configurable triggers and notifications.
- `permanent_ban.json` – escalates repeated abuse to a permanent ban.
- `jitter_warning.json` – lightweight slowdown that introduces randomized backoff without hard bans.

You can embed any of these snippets inside a rule's `actions` array. The placeholders used within the notification payloads (`{{clientIP}}`, `{{endpoint}}`, etc.) are automatically replaced by the notification subsystem.
