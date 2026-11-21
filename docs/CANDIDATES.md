# Candidate vulnerabilities (backlog)

Items in this file are **not registered checks** yet. They are kept here with
enough context to build a module, lab and validation row later. When a check is
implemented, move it to the registry and `docs/CVE-INDEX.md`, and add its
validation row to `labs/VALIDATED.md`; do not leave it duplicated here.

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
