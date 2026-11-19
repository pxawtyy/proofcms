# Candidate vulnerabilities (backlog)

Items in this file are **not registered checks** yet. They are kept here with
enough context to build a module, lab and validation row later. When a check is
implemented, move it to the registry and `docs/CVE-INDEX.md`.

## NGINX HTTP/2 RCE (disclosed 2026-11-18)

Source: <https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities>

Both are unauthenticated remote code execution flaws in NGINX itself, rated
CVSS 4.0 **9.2 (Critical)**. Both require **HTTP/2 enabled** on the target.
Wiz has not released its proof-of-concept exploits.

| CVE | Bug | First affected | Fixed (OSS) | Fixed (NGINX Plus) | Extra conditions |
|---|---|---|---|---|---|
| **CVE-2026-123633** | HTTP/2 connection use-after-free | OSS 1.19.7; Plus R33 / 37.0.0 | **1.30.7 stable**, **1.31.9 mainline** | 37.0.7.1, 37.2.0.1 | Reverse-proxy processing when connection slots run low |
| **CVE-2026-123007** | HTTP/2 `send_window` integer underflow | OSS 1.9.5; Plus R33 / 37.0.0 | **1.30.7 stable**, **1.31.9 mainline** | 37.0.8.1, 37.3.0.1 | 64-bit system; demonstrated over HTTPS/TLS serving static files |

### Notes for the future check

- Detection should require both an affected NGINX version **and** HTTP/2
  enabled. A version-only row is not enough for this pair.
- `http2` on a `listen` directive (older syntax) or `http2 on;` in a server
  block (1.25.1+) are the configuration markers. A safe probe can use
  `curl --http2` / `nghttp` and inspect the negotiated protocol (`h2`) without
  sending malformed frames.
- Without a public memory-corruption PoC, the likely dispositions are
  `BLOCKED_EXTERNAL` or `NOT_YET_VALIDATED` for active exploitation, plus a
  passive/configuration finding. Do not attempt blind heap grooming against
  anything but an isolated, authorized lab.
- Lab idea: NGINX 1.30.6 vs 1.30.7 (or 1.31.8 vs 1.31.9) with a TLS
  server block and HTTP/2 enabled, plus a control with `http2 off;`. A
  crash/worker-respawn differential may be possible for 123633; 123007 needs
  a reliable frame sequence, so treat it as passive until a PoC exists.
- Immediate mitigation: upgrade, or temporarily disable HTTP/2 (`http2 off;`
  on 1.25.1+, and remove the `http2` parameter from `listen` directives),
  reload, and confirm old workers exited.

### Reproduction labs (2026-11-18)

- `labs/cve-2026-123007` - ASAN 1.31.8/1.31.9 builds plus an instrumented
  1.31.8 variant. The verified fix adds `h2c->send_queued`: 1.31.8 lets the
  client claim credit for queued DATA frames and then refunds the same bytes on
  stream cleanup. The default trigger accepts the 8 MB claim, refunds
  7,208,960 bytes, drives `send_window` to 2,150,498,303 (max + 3,014,656) and
  aborts the instrumented worker; 1.31.9 rejects the claim with a flow-control
  violation. A forced `?force_wrap=1` lab request sets `send_window` to
  `2^63 + 0x10000000`, producing a negative `off_t`/shadow size and an ASAN
  `memcpy-param-overlap` in `ngx_ssl_send_chain()`. The real ~55.8 GB
  WINDOW_UPDATE flood is not reproduced end-to-end. Wiz has not published its
  PoC.
- `labs/cve-2026-123633` - proxy stack with `worker_connections 16`, the Wiz
  1-byte-SETTINGS arming and source analysis. The verified fix adds
  `ngx_reusable_connection(h2c->connection, 0)` in `create_stream()`. On
  1.31.8 the drain logs `*1 reusing connection` and sends GOAWAY (frame type
  `0x7`) on the active connection; 1.31.9 keeps it off the reusable queue. The
  Wiz log's freed-pool leak (`0x1010 r->pool`) and `u->peer.free` JOP chain
  are not reproduced.

Both labs are reproduction harnesses, not confirmed RCE proofs.

## Java4Shell (CVE-2026-114938)

- OpenJDK x86-64 Base64 intrinsic out-of-bounds write (`evmovdqub` tail mask
  underflow); `64 x "A" + "="` writes 62 bytes past a 50-byte output buffer.
- Affected: OpenJDK 17.0.6+; fixed 17.0.21.1 (also 21.0.13.1, 25.0.5.1,
  27.0.1.1). Distributions: Temurin, Corretto, Zulu, Liberica, SapMachine,
  Red Hat, Oracle, GraalVM.
- Hardware: x86-64 with `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`
  (Ice Lake+ / Zen 4+); ARM is not affected.
- Lab: `labs/cve-2026-114938` (safe 4096-byte trigger; the current i7-3770 has
  no AVX-512 and reports `BLOCKED_HARDWARE`). Control:
  `-XX:-UseBASE64Intrinsics`.
- Inventory: `tools/java4shell_check.py` (parses `java -version` and CPU flags;
  no malformed input). See `docs/JAVA4SHELL.md`.
- No HTTP module: the trigger is a local Base64 decode, not an application
  endpoint. The public chain (heap grooming/writer/reader) is not included.

## Pending Joomla candidates from the previous batch

| CVE | Component | Type | Fixture still needed |
|---|---|---|---|
| CVE-2026-76602 | Fabrik | unauthenticated ORDER BY SQLi | Fabrik 4.7.0/4.7.1 + 4.7.2 |
| CVE-2026-100752 | OrdaSoft Real Estate Manager | unauthenticated `order_field` SQLi | 6.7.8 + 6.7.9 (module ready) |
| CVE-2026-102782 | OrdaSoft Simple Membership | unauthenticated `checkLoginPass` SQLi | 7.3.x + 7.4.0 (module ready) |
| CVE-2026-77995 | miniOrange OAuth Client | arbitrary account takeover via cookie | OAuth Client <3.2.0 + 3.2.0 |
| CVE-2026-100750 | Regular Labs Modules Anywhere | LFI / SSRF via module attribute overrides | Pro 9.0.5 + fixed |
| CVE-2026-75949 | J-BusinessDirectory | path traversal + upload/delete | vulnerable + fixed (paid) |
| CVE-2026-102780 | TF Content | missing authorization in public RecordController | 2.9.0–2.9.4 + fixed |
| CVE-2026-90901 | Easy Store | SQLi in media delete endpoint | 1.0.0–3.0.0 + fixed |
| CVE-2026-92223 | Joomla core | workflow stage ACL bypass | core 5.4.8/5.4.9 or 6.1.3/6.1.4 (lab setup) |
| CVE-2026-81566 | SP Page Builder | missing `com_menus` permission on menu item save | archives already available (6.0.0/6.10.0) |
| CVE-2026-65878 | SP Page Builder | authenticated arbitrary file delete | archives already available (6.0.0/6.10.0) |
