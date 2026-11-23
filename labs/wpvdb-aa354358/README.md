# WPVDB-aa354358 — paired WordPress 7.1.0 / 7.1.1 comment lab

Negative lab attempt. See `ANALYSIS.md`.

| Service | Image | Port |
|---|---|---|
| `wp-vuln` | wordpress:7.1.0-php8.3-apache | 9220 |
| `wp-fixed` | wordpress:7.1.1-php8.3-apache | 9221 |

## Bring up

```powershell
docker compose -f labs/wpvdb-aa354358/compose.yml up -d
powershell -ExecutionPolicy Bypass -File labs/wpvdb-aa354358/seed.ps1
```

Seed installs each site, enables auto-approved comments and creates post 4.

## Result (2026-11-23)

The 7.1.1 fix makes `wpautop()`'s blockquote rewrite quote-aware. Payloads that
put `>` inside a quoted blockquote attribute were neutralised by comment KSES
before `wpautop()` ran, so both builds rendered the same HTML. No probe.

## Teardown

```powershell
docker compose -f labs/wpvdb-aa354358/compose.yml down -v
```
