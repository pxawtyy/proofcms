# ProofCMS lab validation matrix

This file is the committed record of what is actually confirmed. `reports/`
holds detailed per-run evidence and stays gitignored; the conclusions live
here so the next session starts from knowledge, not from re-derivation.
Every registered check (all four module registries) must have a row:
`tests/test_module_contract.py` enforces a row for every active-probe module
and a row for every registered CVE overall — add or update the row in the
same commit as the module.

Active-probe tables carry `Validated` (date of the last live lab run) and
`Commit` (the commit that shipped the validation) alongside the lab
directory. Passive-only tables record the blocker (missing package, vague
advisory, missing credentials, or no safe harness). Acquire missing fixtures
via [`labs/REQUIREMENTS.md`](REQUIREMENTS.md).

Dispositions:

| Disposition | Meaning |
|---|---|
| CONFIRMED | A PoC ran against the matching vulnerable package in a live local lab. |
| NOT_CONFIRMED | Ran live and did not confirm (e.g. patched control, absent surface). |
| BLOCKED_EXTERNAL | Could not run: missing package, vague advisory, or required access that was not available. The reason is recorded. |
| NOT_YET_VALIDATED | Probe exists (unit-tested) but has not run against a live lab yet. |
| AGGRESSIVE_SENT | Blind payload sent; execution could not be confirmed from the response. |

## WordPress — active probes

| CVE | Fixture (vuln) | Probe | Disposition | Patched control | Lab | Validated | Commit |
|---|---|---|---|---|---|---|---|
| CVE-2020-25213 | WP File Manager 6.0 | aggressive elFinder upload + PHP execution, `rm` cleanup | CONFIRMED | — | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2020-35489 | Contact Form 7 5.3.1 | aggressive control-char filename bypass | CONFIRMED (VULNERABLE_UPLOAD_ONLY; 5.3.2 sanitizes the saved name, so the probe is version-gated, not a standalone patch discriminator) | — | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2023-28121 | — | safe auth bypass | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2023-32243 | Essential Addons Lite 5.7.1 + Pro 5.6.2 | aggressive admin password reset + login (destructive; restore password after run) | CONFIRMED | — | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2023-3460 | Ultimate Member 2.6.6 | aggressive privileged registration | CONFIRMED | — | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2024-10402 | — | safe probe blocked by design (needs Contributor session) | BLOCKED_EXTERNAL (credentialed session required) | — | — | — | — |
| CVE-2024-10924 | Really Simple Security 9.1.1.1 | safe 2FA skip-onboarding bypass | CONFIRMED | 9.1.1.2 NOT_CONFIRMED | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2024-28000 | LiteSpeed Cache 6.3.0.1 | aggressive hash/seed recovery + admin impersonation (Apache) | CONFIRMED | OLS-side impersonation BLOCKED_EXTERNAL (image WAF 403s any request with the `litespeed_role` cookie) | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2026-15748 | Forminator 1.56.1 | aggressive forged select-carried upload validated as upload (mismatched content fails closed; zero files written) | CONFIRMED | 1.56.2 NOT_CONFIRMED | `labs/cve-2026-15748` | 2026-11-09 | `b19782c` |
| CVE-2026-18781 | Drag and Drop Multiple File Upload for CF7 1.3.9.8 (+ CF7 5.9.8 for the control-char strip) | aggressive `.phar` + `.htaccess` RCE | CONFIRMED | 1.3.9.9 NOT_CONFIRMED | `labs/wordpress-plugin-fixtures` | 2026-11-08 | `8a843ee` |
| CVE-2026-32475 | Elementor Pro 3.16.2 archive present but flagged as non-vendor build (see `labs/cve-2026-32475/README.md`) | safe one-shot PHP upload | NOT_YET_VALIDATED (needs vendor-original archive for authoritative validation) | — | — | — | — |
| CVE-2026-60137 | lab `labs/cve-2026-60137` (WP 7.0.1; 6.8.5/6.9.4 share the image) | safe differential SQLi timing (harmless true/false + SLEEP, 3 paired probes, no extraction) | CONFIRMED | 7.0.2 PATCHED (version gate skips probe) | `labs/cve-2026-60137` | 2026-11-09 | `COMMIT60137` | — |
| CVE-2026-63030 | lab `labs/cve-2026-60137` (shared WP image) | safe REST batch confusion | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-64638 | — | safe reflected XSS on login | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-87902 | lab `labs/cve-2026-87902` (WP 7.0.2) | safe differential path traversal | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-92229 | Forminator 1.57.2 | safe registered-shortcode evaluation differential via preview quiz renderer | CONFIRMED | 1.57.3 NOT_CONFIRMED (input sanitizer strips the embedded shortcode) | `labs/cve-2026-92229` | 2026-11-09 | `9ddcd69` |

## WordPress — passive-only (out of contract scope; tracked for sourcing)

| CVE | Note |
|---|---|
| CVE-2024-6220 (Keydatas) | BLOCKED_EXTERNAL: vulnerable branch (<=2.5.2) unsourcable (versioned zip 404s, plugins Trac bot-walled); wordpress.org currently serves patched 2.8.1. |
| CVE-2026-6692 (Slider Revolution) | Parked: 7.0.6 front AJAX is read-only and upload handlers enforce mime/extension; needs the advisory detail or a 7.0.10/7.0.11 diff. |
| CVE-2024-4439 | Passive advisory only (`exploit_modes` empty; PoC recorded as metadata but never sent automatically): unauthenticated stored XSS in the Avatar block, WP 6.0.x–6.5.1 branch backports. No fixture needed — version detection from the core manifest. |
| WPVDB-df1ca42d-b835-4ed6-a634-3f62ac020e77 | Passive advisory only (WPScan ID, no CVE): core comment-moderation stored XSS, branch-specific fixes. No fixture needed — version detection. |
| WPVDB-aa354358-3a32-4e81-8628-d1aa917b5efa | Passive advisory only (WPScan ID, no CVE): core comment stored XSS, branch-specific fixes. No fixture needed — version detection. |
| WPVDB-5e9804e5-bbd4-4836-a5f0-b4388cc39225 | Passive advisory only (WPScan ID, no CVE): core insecure deserialization, branch-specific fixes. No fixture needed — version detection. |

## Joomla — active probes

| CVE | Fixture (vuln) | Probe | Disposition | Patched control | Lab | Validated | Commit |
|---|---|---|---|---|---|---|---|
| CVE-2010-4166 | Joomla 1.5.21 package retained | safe filter_order SQLi | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2015-7857 | — | safe content-history SQLi | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2015-8562 | Joomla 3.4.4 (PHP 5.6) | aggressive header PHP-object-injection | AGGRESSIVE_SENT (blind; marker not executed — needs PHP 5.4/5.5 session-handler fixture) | — | — | — | — |
| CVE-2016-8869 | Joomla 3.6.3 (`allowUserRegistration=0`) | aggressive group-7 registration + admin login | CONFIRMED | 3.7.0 PATCHED (`user.register` removed) | `labs/cve-2016-8869` | 2026-11-09 | `12814af` |
| CVE-2016-8870 | Joomla 3.6.3 (`allowUserRegistration=0`) | aggressive `user.register` account creation | CONFIRMED | 3.7.0 PATCHED | `labs/cve-2016-8869` | 2026-11-09 | `12814af` |
| CVE-2017-8917 | Joomla 3.7.0 | aggressive `extractvalue()` marker + SLEEP fallback (read-only) | CONFIRMED | 3.8.11 NOT_CONFIRMED | `labs/cve-2017-8917` | 2026-11-09 | `12814af` |
| CVE-2018-15882 | Joomla 3.8.11 | aggressive short-tag PHAR-stub GIF via admin media manager | CONFIRMED (VULNERABLE_UPLOAD_ONLY; inert marker file) | 3.8.12 NOT_CONFIRMED | `labs/cve-2018-15882` | 2026-11-09 | `12814af` |
| CVE-2019-19576 | K2 2.6.8 archive retained | aggressive Verot `.phar` dangerous-file bypass | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2019-19634 | K2 2.6.8 archive retained | aggressive Verot `.pht` dangerous-file bypass | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2024-40744 | Convert Forms 5.0.4 archive retained | safe upload | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-102426 | SP Page Builder 3.8.9/6.0.0 | safe DCF XSS reflection | NOT_CONFIRMED (marker not reflected; 6.0.0 outside module range — possible range gap, review separately) | 6.10.0 NOT_AFFECTED per module | — | — | — |
| CVE-2026-21627 | lab `labs/cve-2026-21627` (nrframework via Convert Forms 5.0.4) | safe access control | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-48907 | JCE 2.9.99.x archives retained | safe upload route | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-48908 | SP Page Builder 6.0.0 (Joomla 5.4.9) | aggressive icon-package upload + `.htaccess`/non-PHP RCE | CONFIRMED | 3.8.9 NOT_CONFIRMED (no handler); 6.10.0 PATCHED (403) | `labs/cve-2026-48908` | 2026-11-09 | `12814af` |
| CVE-2026-48939 | iCagenda 3.7.21 archive retained | aggressive upload | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-49049 | Helix3 2.2 archive retained | safe/aggressive AJAX handler | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-56290 | Page Builder CK (ambiguous 1.x/2.x/3.x range) | aggressive upload | NOT_YET_VALIDATED (needs exact PoC-confirmed archive) | — | — | — | — |
| CVE-2026-56291 | Balbooa Forms 2.4.3.1/2.4.4.0 | aggressive upload (forced) | PATCHED (both; source already has `checkToken`) | 2.4.0 BLOCKED_EXTERNAL (no archive) | — | — | — |
| CVE-2026-56292 | — | safe SQLi | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-57827 | RSFiles 1.16.29 | aggressive session-warmed upload + RCE | CONFIRMED | 1.17.12 BLOCKED_EXTERNAL (no archive) | `labs/cve-2026-57827` | 2026-11-09 | `12814af` |
| CVE-2026-57829 | Helix Ultimate 1.1.4/2.2.4 archives retained | safe stored XSS | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-57830 | Helix Ultimate 2.2.4/2.2.6 | safe file deletion (disposable files) | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-71573 | — | safe CORS origin validation | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-73373 | Joomla 5.4.7 package retained | safe SHTML upload (needs upload surface; Convert Forms field usable) | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-78079 | Helix Ultimate 1.0-2.2.9 archives retained | safe open redirect | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-90915 | Joomla 5.4.8 | aggressive canary directory deletion via cache purge | CONFIRMED | 5.4.9 NOT_CONFIRMED (HTTP 500, canary intact) | `labs/cve-2026-90915` | 2026-11-09 | `12814af` |
| CVE-2026-94132 | — | safe mailbox attachment RCE vector | NOT_YET_VALIDATED | — | — | — | — |

## Joomla — passive-only (out of contract scope; tracked for sourcing)

| CVE | Note |
|---|---|
| CVE-2025-26854 (Articles Good Search) | BLOCKED_EXTERNAL: needs 1.2.4.0011 package. |
| CVE-2026-61424 (DJ-Classifieds) | BLOCKED_EXTERNAL: local `dj_classifieds_3.11` archive is data exports only, not an installable extension; needs complete 3.11.1. |
| CVE-2026-92222 (core SSRF) | No active proof: JSST advisory names no endpoint/parameter and 5.4.8→5.4.9 shows broad hardening; CVE requires high privileges. |
| PROOFCMS-K2-REGISTRATION-AVATAR | Companion surface probe (no CVE): reports the public K2 registration avatar upload surface used by CVE-2019-19576/19634. Passive detection only — needs Joomla + K2 with public registration enabled. |

## Generic web libraries — active probes

| CVE | Fixture | Probe | Disposition | Patched control | Lab | Validated | Commit |
|---|---|---|---|---|---|---|---|
| CVE-2018-9206 | lab `labs/cve-2018-9206` (blueimp v9.22.0) | safe upload | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2021-23394 | elFinder tags retained | safe upload | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-111497 | — | safe node2shell | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-81891 | lab `labs/cve-2026-81891` (elFinder 2.1.69/2.1.70) | safe text-only `.phtml` differential (direct upload must fail, ZIP extraction tested) | NOT_YET_VALIDATED | — | — | — | — |

## Generic web libraries — passive-only (version/config detection; no active proof)

| CVE | Note |
|---|---|
| CVE-2018-8284 (.NET RCE) | Passive version detection only: legacy .NET Framework branches before the Microsoft security updates; exploitation needs Windows + OS/build prerequisites, no lab harness. |
| CVE-2023-21722 (.NET DoS) | Passive version detection only: exact servicing build required; no lab harness. |
| CVE-2023-36560 (ASP.NET bypass) | Passive version detection only: exact servicing build required; no lab harness. |
| CVE-2023-36899 (ASP.NET EoP) | Passive version detection only: needs IIS/.NET app-pool and OS prerequisites; no lab harness. |
| CVE-2026-42945 (NGINX rewrite) | Passive version/config detection only: needs a vulnerable rewrite directive sequence; memory-corruption proof has no safe lab harness. |
| CVE-2026-9256 (NGINX rewrite captures) | Passive version/config detection only: needs vulnerable rewrite captures; no safe lab harness. |
| CVE-2026-42530 (NGINX HTTP/3 UAF) | Passive version/config detection only: needs HTTP/3 + `ngx_http_v3_module`; no safe lab harness. |
| CVE-2026-90439 (NGINX HTTP/3 overflow) | Passive version/config detection only: needs HTTP/3 + `ngx_http_v3_module`; no safe lab harness. |
| CVE-2026-42055 (NGINX proxy-v2/gRPC) | Passive version/config detection only: needs proxy-v2 or gRPC configuration; no safe lab harness. |
| CVE-2026-42533 (NGINX map-regex) | Passive version/config detection only: needs a vulnerable map regex; no safe lab harness. |
| CVE-2026-56434 (NGINX SSI UAF) | Passive version/config detection only: needs `ngx_http_ssi_module` configured; no safe lab harness. |
| CVE-2026-60005 (NGINX slice) | Passive version/config detection only: needs `ngx_http_slice_module` configured; no safe lab harness. |

## PHP runtimes — active probes

| CVE | Fixture | Probe | Disposition | Patched control | Lab | Validated | Commit |
|---|---|---|---|---|---|---|---|
| CVE-2012-1823 | PHP-CGI historical fixture per REQUIREMENTS | safe | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2024-4577 | Windows PHP-CGI lab per REQUIREMENTS | safe | NOT_YET_VALIDATED (needs Windows VM/container host) | — | — | — | — |
| CVE-2019-11043 | lab `labs/cve-2019-11043` (PHP-FPM 7.3.10 + nginx vulnerable PATH_INFO config) | passive detector only (`exploit_modes` empty) | NOT_YET_VALIDATED (lab exists; no active proof implemented) | — | `labs/cve-2019-11043` | — | — |
| CVE-2026-109618 | lab `labs/cve-2026-109618` (PHP 8.3.35 mod_php, single worker, memory_limit=16M) | aggressive OOM-shape crash differential: worker death + PID respawn vs clean fatal | CONFIRMED | 8.3.36 NOT_CONFIRMED (HTTP 200 fatal + same PID; version gate reports PATCHED) | `labs/cve-2026-109618` | 2026-11-09 | `4849634` |
| CVE-2026-109619 | lab `labs/cve-2026-109619` (PHP 8.2.34 mod_php, single worker, 8M + 1MB cookie_path) | aggressive OOM-gate differential (follow-up dies vs clean + fresh cookie) + safe stale-PSID leak differential on cli-server lab (4096-byte Set-Cookie vs fresh 32B) | CONFIRMED | 8.2.35 NOT_CONFIRMED (follow-up 200 + fresh cookie; version gate reports PATCHED); 8.3.36 cli-server NOT_CONFIRMED (fresh 32B) | `labs/cve-2026-109619` + `labs/cve-2026-109619-cli` | 2026-11-09 | `f49e6bc` |
