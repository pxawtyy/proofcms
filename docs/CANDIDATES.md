# Candidate vulnerabilities (backlog)

Items in this file are **not registered checks** yet. They are kept here with
enough context to build a module, lab and validation row later. When a check is
implemented, move it to the registry and `docs/CVE-INDEX.md`, and add its
validation row to `labs/VALIDATED.md`; do not leave it duplicated here.

## NGINX HTTP/2 RCE (disclosed 2026-11-18)

Source: <https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities>

This is an unauthenticated remote code execution flaw in NGINX itself, rated
CVSS 4.0 **9.2 (Critical)**. It requires **HTTP/2 enabled** on the target.
Wiz has not released its proof-of-concept exploit.

| CVE | Bug | First affected | Fixed (OSS) | Fixed (NGINX Plus) | Extra conditions |
|---|---|---|---|---|---|
| **CVE-2026-123007** | HTTP/2 `send_window` integer underflow | OSS 1.9.5; Plus R33 / 37.0.0 | **1.30.7 stable**, **1.31.9 mainline** | 37.0.8.1, 37.3.0.1 | 64-bit system; demonstrated over HTTPS/TLS serving static files |

### Notes for the future check

- Detection should require both an affected NGINX version **and** HTTP/2
  enabled. A version-only row is not enough for this defect.
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
The lab is a reproduction harness, not a confirmed RCE proof.

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

## Pending Joomla candidates

| CVE | Component | Type | Fixture still needed |
|---|---|---|---|
| CVE-2026-76602 | Fabrik | unauthenticated ORDER BY SQLi | Fabrik 4.7.0/4.7.1 + 4.7.2 |
| CVE-2026-102780 | TF Content | missing authorization in public RecordController | 2.9.0-2.9.4 + fixed |

All other candidates that previously appeared in this file now have a
registered module, a `docs/CVE-INDEX.md` row and a `labs/VALIDATED.md`
disposition; use those registries instead of this backlog.
