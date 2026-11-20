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

## VMware vCenter authentication bypass (CVE-2026-123890)

Source: [VMSA-2026-0009.1](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495),
CVSS 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), CWE-288.

Affected: vCenter 9.1.x before 9.1.1.0200, 9.0.x before 9.0.2.0200, 8.0
before 8.0 U3m, 5.x before 5.2.5; 7.0 under extended support. Telco Cloud
Platform 3.0/4.x/5.0.x/5.1.x/5.2 and Telco Cloud Infrastructure 3.0 are also
listed (KB463116). No workaround.

**Disposition: `BLOCKED_EXTERNAL`.** The advisory only says the bypass is in
the VMware Directory Service; there is no public PoC, endpoint, parameter, or
request/response detail (CISA SSVC: exploitation `none`, automatable `yes`).
vCenter is a proprietary multi-GB appliance, not in the lab archive, and it is
not a CMS surface. A version-only detector would require a new vCenter product
detector and would not prove the bypass; do not add a check until a public
technical write-up or a reproducible appliance fixture exists.

## Ruby2Shell (CVE-2026-132825)

- One-byte heap overflow in Ruby's single-byte `case_map()` during
  `upcase`/`swapcase`/`downcase(:fold)`/`casecmp?` on ISO-8859-x and
  Windows-125x strings.
- Affected: 3.3.0-3.3.13, 3.4.0-3.4.12, 4.0.0-4.0.9; Ruby 3.2 and older are
  EOL and affected. Fixed: 3.3.14, 3.4.13, 4.0.10 (commit `d582f8f13d70`).
- GHSA-34m4-m9fh-gqp5 rates it **Critical**; NVD scores 7.4 (`AV:L/AC:H`).
  Veria Labs claims RCE on stock Rails and plans a public PoC for 2026-11-25;
  independent research reproduces the ASAN crash and a glibc chunk-header
  corruption, but not an end-to-end RCE.
- Inventory: `tools/ruby2shell_check.py`. Lab: `labs/cve-2026-132825`
  (Valgrind, 21 x `0xDF` ISO-8859-1, Ruby 3.4.12 vs 3.4.13). **CONFIRMED**
  for the one-byte out-of-bounds write; RCE not reproduced.

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

## ASP.NET and .NET candidates

| CVE | Component | Type | Status / fixture needed |
|---|---|---|---|
| CVE-2025-55315 | ASP.NET Core Kestrel | request smuggling | CONFIRMED (`labs/cve-2025-55315`) |
| CVE-2026-88092 | ASP.NET Core Kestrel | aborted-connection request smuggling (CWE-444) | 8.0.0–8.0.31, 9.0.0–9.0.20, 10.0.0–10.0.12, 11 preview1–rc1; fixed 8.0.32/9.0.21/10.0.13/11 rc2; CONFIRMED (`labs/cve-2026-88092`) |
| CVE-2020-0688 | Exchange ViewState | deserialization RCE | passive build/surface module; active BLOCKED (Exchange/Windows fixture) |
| CVE-2026-40372 | ASP.NET Core DataProtection | signature verification bypass / forged cookies (CWE-347) | 10.0.0–10.0.6 (netstandard2.0/net462 managed asset); fixed 10.0.7; CONFIRMED (`labs/cve-2026-40372`) |
| CVE-2026-114146 | ASP.NET Core SignalR | identity binding / EoP (CWE-863) | 1.2.0–1.2.13 and runtimes 8.0 ≤8.0.33 / 9.0 ≤9.0.22 / 10.0 ≤10.0.14 / 11.0 ≤rc.3; fixed 1.2.14 / 8.0.34 / 9.0.23 / 10.0.15 / 11.0.0; CONFIRMED (`labs/cve-2026-114146`) |
| CVE-2026-70188 | ASP.NET Core Kestrel | HTTP/2 trailer/HPACK newline smuggling (CWE-444) | 8.0.0–8.0.31, 9.0.0–9.0.20, 10.0.0–10.0.12, 11 preview1–rc1; fixed 8.0.32/9.0.21/10.0.13/11 rc2; CONFIRMED (`labs/cve-2026-70188`) |

## Pending Joomla candidates from the previous batch

| CVE | Component | Type | Fixture still needed |
|---|---|---|---|
| CVE-2026-76602 | Fabrik | unauthenticated ORDER BY SQLi | Fabrik 4.7.0/4.7.1 + 4.7.2 |
| CVE-2026-100752 | OrdaSoft Real Estate Manager | unauthenticated `order_field` SQLi | 6.7.8 + 6.7.9 (module ready) |
| CVE-2026-102782 | OrdaSoft Simple Membership | unauthenticated `checkLoginPass` SQLi | 7.3.x + 7.4.0 (module ready) |
| CVE-2026-77995 | miniOrange OAuth Client | arbitrary account takeover via SSO bridge cookies | 1.0.0–3.1.9, fixed 3.2.0; CONFIRMED (`labs/cve-2026-77995`, Joomla 3.9 + documented J3-branch shim, 3.1.4 vs 3.2.2) |
| CVE-2026-100750 | Regular Labs Modules Anywhere | LFI / SSRF via module attribute overrides | Pro 9.0.5 + fixed |
| CVE-2026-75949 | J-BusinessDirectory | path traversal + upload/delete; 1.0.0–6.2.2, fixed 6.2.3 | CONFIRMED (`labs/cve-2026-75949`) |
| CVE-2026-102780 | TF Content | missing authorization in public RecordController | 2.9.0–2.9.4 + fixed |
| CVE-2026-90901 | Easy Store | SQLi in media delete endpoint | 1.0.0–3.0.0 + fixed |
| CVE-2026-92223 | Joomla core | workflow stage batch ACL bypass; 5.0.0–5.4.8 and 6.0.0–6.1.3, fixed 5.4.9/6.1.4 | CONFIRMED (`labs/cve-2026-92223`) |
| CVE-2026-65878 | SP Page Builder | authenticated arbitrary file rename/delete via the media `thumb`; 1.0.0–6.7.0, fixed 6.7.1 | CONFIRMED (`labs/cve-2026-48908`, 6.0.0 vs 6.10.0) |
| CVE-2026-65766 | SP Page Builder | Dynamic Content `direction` ORDER BY SQLi; 1.0.0–6.7.0, fixed 6.7.1 | CONFIRMED (`labs/cve-2026-65766`, 6.7.0 vs 6.10.0) |
| CVE-2026-67285 | SP Page Builder | addon-name local PHP file inclusion via the editor preview; 1.0.0–6.7.0, fixed 6.8.0 | CONFIRMED (`labs/cve-2026-65766`, 6.7.0 vs 6.10.0) |
| CVE-2026-105606 | Custom Tables | unauthenticated file upload via `view=fileuploader`; 1.0–3.7.7, fixed 3.7.8 | CONFIRMED (`labs/cve-2026-105606`, 3.7.7 vs 3.7.8) |
| CVE-2026-65879 | SP Page Builder | unauthenticated mail relay via product-wide form salt; 1.0.0–6.7.0, fixed 6.7.1 | CONFIRMED (`labs/cve-2026-65879`, 6.0.0 vs 6.10.0 + GreenMail) |
