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
| CVE-2026-60137 | lab `labs/cve-2026-60137` (WP 7.0.1; 6.8.5/6.9.4 share the image) | safe differential SQLi timing (harmless true/false + SLEEP, 3 paired probes, no extraction) | CONFIRMED | 7.0.2 PATCHED (version gate skips probe) | `labs/cve-2026-60137` | 2026-11-09 | `3d9f0f5` |
| CVE-2026-63030 | lab `labs/cve-2026-60137` (shared WP image) | safe REST batch confusion | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-64638 | — | safe reflected XSS on login | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-87902 | lab `labs/cve-2026-87902` (WP 7.0.2) | safe differential path traversal (wp-links-opml.php page_id=2 depth=4 vs randomized control, read-only) | CONFIRMED | 7.1.2 PATCHED (version gate skips probe) | `labs/cve-2026-87902` | 2026-11-09 | `86b8cc3` | — |
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
| CVE-2015-8562 | lab `labs/cve-2015-8562` (Joomla 3.4.4 on PHP 5.6.27, mysqli; vendor 3.4.4 full package) | aggressive header PHP-object-injection (blind; timing differential attempted, no execution observed) | AGGRESSIVE_SENT (probe runs green against the lab; CONFIRMED blocked: gadget needs header NULs, rejected with HTTP 400 by Apache 2.4.10/2.4.25; literal-`\0` form cannot bind after the mysqli round-trip; multipart-filename breakout unsolved) | 3.4.6+ out of scope (no fixed-branch PHP 5.x fixture) | `labs/cve-2015-8562` | 2026-11-09 | `adec193` |
| CVE-2016-8869 | Joomla 3.6.3 (`allowUserRegistration=0`) | aggressive group-7 registration + admin login | CONFIRMED | 3.7.0 PATCHED (`user.register` removed) | `labs/cve-2016-8869` | 2026-11-09 | `12814af` |
| CVE-2016-8870 | Joomla 3.6.3 (`allowUserRegistration=0`) | aggressive `user.register` account creation | CONFIRMED | 3.7.0 PATCHED | `labs/cve-2016-8869` | 2026-11-09 | `12814af` |
| CVE-2017-8917 | Joomla 3.7.0 | aggressive `extractvalue()` marker + SLEEP fallback (read-only) | CONFIRMED | 3.8.11 NOT_CONFIRMED | `labs/cve-2017-8917` | 2026-11-09 | `12814af` |
| CVE-2018-15882 | Joomla 3.8.11 | aggressive short-tag PHAR-stub GIF via admin media manager | CONFIRMED (VULNERABLE_UPLOAD_ONLY; inert marker file) | 3.8.12 NOT_CONFIRMED | `labs/cve-2018-15882` | 2026-11-09 | `12814af` |
| CVE-2019-19576 | K2 2.8.0 (CVE-reported; git-sourced release tree) on Joomla 3.6.3/PHP 5.6.27 | aggressive backend item-save inert binary `.phar` attachment + marker readback (admin creds via --aggressive-arg) | CONFIRMED (VULNERABLE_UPLOAD_ONLY) | 2.28 NOT_CONFIRMED (handler deny-list rejects; 2.11.20240911 still stores+serves plain .phar — file_new_name_ext defeats the lib rename, so the gate does not treat it as fixed) | `labs/cve-2019-19576` | 2026-11-10 | `27d8136` |
| CVE-2019-19634 | K2 2.8.0 (CVE-reported; git-sourced release tree) on Joomla 3.6.3/PHP 5.6.27 | aggressive backend item-save inert binary `.pht` attachment + marker readback (admin creds via --aggressive-arg) | CONFIRMED (VULNERABLE_UPLOAD_ONLY) | 2.28 NOT_CONFIRMED (aligned deny-list incl. .pht; 2.27 still serves .pht, so the gate requires 2.28) | `labs/cve-2019-19576` | 2026-11-10 | `27d8136` |
| CVE-2024-40744 | Convert Forms 4.4.5 (last release before the extension check; official free ZIP) on Joomla 5.2.3/PHP 8.3 | safe unauthenticated GIF89a+PHP polyglot upload to web-accessible tmp/ with runtime execution marker (self-deleting) | CONFIRMED (VULNERABLE) | 4.4.6 NOT_CONFIRMED (identical form; extension gate rejects, nothing stored) | `labs/cve-2024-40744` | 2026-11-10 | `3b560f5` |
| CVE-2026-102426 | SP Page Builder 3.8.9/6.0.0 | safe DCF XSS reflection | NOT_CONFIRMED (marker not reflected; 6.0.0 outside module range — possible range gap, review separately) | 6.10.0 NOT_AFFECTED per module | — | — | — |
| CVE-2026-21627 | lab `labs/cve-2026-21627` (nrframework 6.0.15 via Convert Forms 5.0.4) | safe access control (unauthenticated gadget write + readback + self-delete, no executable content) | CONFIRMED | 6.0.38 via Convert Forms 5.1.0 PATCHED (version gate skips probe) | `labs/cve-2026-21627` | 2026-11-09 | `394201b` |
| CVE-2026-48907 | JCE 2.9.99.1 (installer package, official Widget Factory tree) on Joomla 5.2.3/PHP 8.3 | safe unauthenticated profiles.import GIF89a+PHP polyglot upload to web-accessible tmp/ with runtime execution marker (self-deleting) | CONFIRMED (VULNERABLE) | 2.9.99.13 NOT_CONFIRMED (import POST rejected HTTP 403, nothing stored) | `labs/cve-2026-48907` | 2026-11-10 | `917bfa6` |
| CVE-2026-48908 | SP Page Builder 6.0.0 (Joomla 5.4.9) | aggressive icon-package upload + `.htaccess`/non-PHP RCE | CONFIRMED | 3.8.9 NOT_CONFIRMED (no handler); 6.10.0 PATCHED (403) | `labs/cve-2026-48908` | 2026-11-09 | `12814af` |
| CVE-2026-48939 | iCagenda 4.0.7 (official Core package) on Joomla 6.1.0-rc1/PHP 8.4 (the RCE window: framework block absent until 6.1.2) | aggressive guest submit.submit jform[file] PHP polyglot upload to web-accessible attachments/ with runtime execution marker (self-deleting) | CONFIRMED (VULNERABLE) | 4.0.8 NOT_CONFIRMED (canUpload gates reject; nothing stored) | `labs/cve-2026-48939` | 2026-11-10 | `9366fc5` |
| CVE-2026-49049 | Helix3 2.2 (installer package) on Joomla 3.10/PHP 7.4 | aggressive unauthenticated layout save + path-traversal write to web root with public marker readback (cleanup verified where possible) | CONFIRMED (VULNERABLE or VULNERABLE_UPLOAD_ONLY) | j3-security-v1.0.0 NOT_CONFIRMED (admin-only + CSRF-gated AJAX, sanitized names, realpath traversal blocks; nothing written) | `labs/cve-2026-49049` | 2026-11-10 | `04140d8` |
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
| CVE-2018-9206 | lab `labs/cve-2018-9206` (blueimp v9.22.0) | safe upload (inert text file, upload + readback + handler delete, no executable content) | CONFIRMED (VULNERABLE_UPLOAD_ONLY) | 9.22.1 PATCHED (version gate skips probe) | `labs/cve-2018-9206` | 2026-11-09 | `1f39981` |
| CVE-2021-23394 | lab `labs/cve-2021-23394` (elFinder 2.1.57 vuln :9157 / 2.1.58 patched :9158) | safe inert `.phar` upload (missing PHAR MIME denial, no PHP code, cleaned via connector rm) | CONFIRMED (VULNERABLE_UPLOAD_ONLY) | 2.1.58 PATCHED (version gate skips probe) | `labs/cve-2021-23394` | 2026-11-09 | `65d091d` |
| CVE-2026-111497 | — | safe node2shell | NOT_YET_VALIDATED | — | — | — | — |
| CVE-2026-81891 | lab `labs/cve-2026-81891` (elFinder 2.1.69/2.1.70) | safe text-only `.phtml` differential (direct upload must fail, ZIP extraction tested) | CONFIRMED (VULNERABLE_UPLOAD_ONLY; inert marker file) | 2.1.70 PATCHED (version gate skips probe) | `labs/cve-2026-81891` | 2026-11-09 | `656b3c4` |

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
| CVE-2012-1823 | lab `labs/cve-2012-1823` (PHP 5.3.12 CGI built from museum source + classic Action/AddHandler mapping) | safe marker execution from request body (`auto_prepend_file=php://input`, no files written) | CONFIRMED | same binary without the CGI mapping: probe runs (5.3.12 detected) but marker not returned (NOT_CONFIRMED) | `labs/cve-2012-1823` | 2026-11-09 | `24f32a1` |
| CVE-2024-4577 | Windows PHP-CGI lab per REQUIREMENTS | safe | NOT_YET_VALIDATED (needs Windows VM/container host) | — | — | — | — |
| CVE-2019-11043 | lab `labs/cve-2019-11043` (PHP-FPM 7.3.10 + nginx vulnerable PATH_INFO config) | passive detector only (`exploit_modes` empty) | NOT_YET_VALIDATED (lab exists; no active proof implemented) | — | `labs/cve-2019-11043` | — | — |
| CVE-2026-109618 | lab `labs/cve-2026-109618` (PHP 8.3.35 mod_php, single worker, memory_limit=16M) | aggressive OOM-shape crash differential: worker death + PID respawn vs clean fatal | CONFIRMED | 8.3.36 NOT_CONFIRMED (HTTP 200 fatal + same PID; version gate reports PATCHED) | `labs/cve-2026-109618` | 2026-11-09 | `4849634` |
| CVE-2026-109619 | lab `labs/cve-2026-109619` (PHP 8.2.34 mod_php, single worker, 8M + 1MB cookie_path) | aggressive OOM-gate differential (follow-up dies vs clean + fresh cookie) + safe stale-PSID leak differential on cli-server lab (4096-byte Set-Cookie vs fresh 32B) | CONFIRMED | 8.2.35 NOT_CONFIRMED (follow-up 200 + fresh cookie; version gate reports PATCHED); 8.3.36 cli-server NOT_CONFIRMED (fresh 32B) | `labs/cve-2026-109619` + `labs/cve-2026-109619-cli` | 2026-11-09 | `f49e6bc` |
