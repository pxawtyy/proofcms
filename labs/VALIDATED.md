# ProofCMS lab validation matrix

Seed of the item-1 tracking doc (2026-11-09): every module that advertises
active exploit modes (`exploit_modes` non-empty in its `metadata()`) must have
a disposition row here. `tests/test_module_contract.py` enforces that rule —
add or update the row in the same commit as the module.

Dispositions:

| Disposition | Meaning |
|---|---|
| CONFIRMED | A PoC ran against the matching vulnerable package in a live local lab. |
| NOT_CONFIRMED | Ran live and did not confirm (e.g. patched control, absent surface). |
| BLOCKED_EXTERNAL | Could not run: missing package, vague advisory, or required access that was not available. The reason is recorded. |
| NOT_YET_VALIDATED | Probe exists (unit-tested) but has not run against a live lab yet. |
| AGGRESSIVE_SENT | Blind payload sent; execution could not be confirmed from the response. |

`reports/` holds detailed per-run evidence and stays gitignored; this file
records only the conclusions. Acquire missing fixtures via
[`labs/REQUIREMENTS.md`](REQUIREMENTS.md).

## WordPress — active probes

| CVE | Fixture (vuln) | Probe | Disposition | Patched control |
|---|---|---|---|---|
| CVE-2020-25213 | WP File Manager 6.0 | aggressive elFinder upload + PHP execution, `rm` cleanup | CONFIRMED | — |
| CVE-2020-35489 | Contact Form 7 5.3.1 | aggressive control-char filename bypass | CONFIRMED (VULNERABLE_UPLOAD_ONLY; 5.3.2 sanitizes the saved name, so the probe is version-gated, not a standalone patch discriminator) | — |
| CVE-2023-28121 | — | safe auth bypass | NOT_YET_VALIDATED | — |
| CVE-2023-32243 | Essential Addons Lite 5.7.1 + Pro 5.6.2 | aggressive admin password reset + login (destructive; restore password after run) | CONFIRMED | — |
| CVE-2023-3460 | Ultimate Member 2.6.6 | aggressive privileged registration | CONFIRMED | — |
| CVE-2024-10402 | — | safe probe blocked by design (needs Contributor session) | BLOCKED_EXTERNAL (credentialed session required) | — |
| CVE-2024-10924 | Really Simple Security 9.1.1.1 | safe 2FA skip-onboarding bypass | CONFIRMED | 9.1.1.2 NOT_CONFIRMED |
| CVE-2024-28000 | LiteSpeed Cache 6.3.0.1 | aggressive hash/seed recovery + admin impersonation (Apache) | CONFIRMED | OLS-side impersonation BLOCKED_EXTERNAL (image WAF 403s any request with the `litespeed_role` cookie) |
| CVE-2026-15748 | Forminator 1.56.1 | aggressive forged select-carried upload validated as upload (mismatched content fails closed; zero files written) | CONFIRMED | 1.56.2 NOT_CONFIRMED |
| CVE-2026-18781 | Drag and Drop Multiple File Upload for CF7 1.3.9.8 (+ CF7 5.9.8 for the control-char strip) | aggressive `.phar` + `.htaccess` RCE | CONFIRMED | 1.3.9.9 NOT_CONFIRMED |
| CVE-2026-32475 | Elementor Pro 3.16.2 archive present but flagged as non-vendor build (see `labs/cve-2026-32475/README.md`) | safe one-shot PHP upload | NOT_YET_VALIDATED (needs vendor-original archive for authoritative validation) | — |
| CVE-2026-60137 | lab `labs/cve-2026-60137` (WP 6.8.5/6.9.4/7.0.1) | safe differential SQLi timing | NOT_YET_VALIDATED | — |
| CVE-2026-63030 | lab `labs/cve-2026-60137` (shared WP image) | safe REST batch confusion | NOT_YET_VALIDATED | — |
| CVE-2026-64638 | — | safe reflected XSS on login | NOT_YET_VALIDATED | — |
| CVE-2026-87902 | lab `labs/cve-2026-87902` (WP 7.0.2) | safe differential path traversal | NOT_YET_VALIDATED | — |
| CVE-2026-92229 | Forminator 1.57.2 | safe registered-shortcode evaluation differential via preview quiz renderer | CONFIRMED | 1.57.3 NOT_CONFIRMED |

## WordPress — passive-only (out of contract scope; tracked for sourcing)

| CVE | Note |
|---|---|
| CVE-2024-6220 (Keydatas) | BLOCKED_EXTERNAL: vulnerable branch (<=2.5.2) unsourcable (versioned zip 404s, plugins Trac bot-walled); wordpress.org currently serves patched 2.8.1. |
| CVE-2026-6692 (Slider Revolution) | Parked: 7.0.6 front AJAX is read-only and upload handlers enforce mime/extension; needs the advisory detail or a 7.0.10/7.0.11 diff. |

## Joomla — active probes

| CVE | Fixture (vuln) | Probe | Disposition | Patched control |
|---|---|---|---|---|
| CVE-2010-4166 | Joomla 1.5.21 package retained | safe filter_order SQLi | NOT_YET_VALIDATED | — |
| CVE-2015-7857 | — | safe content-history SQLi | NOT_YET_VALIDATED | — |
| CVE-2015-8562 | Joomla 3.4.4 (PHP 5.6) | aggressive header PHP-object-injection | AGGRESSIVE_SENT (blind; marker not executed — needs PHP 5.4/5.5 session-handler fixture) | — |
| CVE-2016-8869 | Joomla 3.6.3 (`allowUserRegistration=0`) | aggressive group-7 registration + admin login | CONFIRMED | 3.7.0 PATCHED (`user.register` removed) |
| CVE-2016-8870 | Joomla 3.6.3 (`allowUserRegistration=0`) | aggressive `user.register` account creation | CONFIRMED | 3.7.0 PATCHED |
| CVE-2017-8917 | Joomla 3.7.0 | aggressive `extractvalue()` marker + SLEEP fallback (read-only) | CONFIRMED | 3.8.11 NOT_CONFIRMED |
| CVE-2018-15882 | Joomla 3.8.11 | aggressive short-tag PHAR-stub GIF via admin media manager | CONFIRMED (VULNERABLE_UPLOAD_ONLY; inert marker file) | 3.8.12 NOT_CONFIRMED |
| CVE-2019-19576 | K2 2.6.8 archive retained | aggressive Verot `.phar` dangerous-file bypass | NOT_YET_VALIDATED | — |
| CVE-2019-19634 | K2 2.6.8 archive retained | aggressive Verot `.pht` dangerous-file bypass | NOT_YET_VALIDATED | — |
| CVE-2024-40744 | Convert Forms 5.0.4 archive retained | safe upload | NOT_YET_VALIDATED | — |
| CVE-2026-102426 | SP Page Builder 3.8.9/6.0.0 | safe DCF XSS reflection | NOT_CONFIRMED (marker not reflected; 6.0.0 outside module range — possible range gap, review separately) | 6.10.0 NOT_AFFECTED per module |
| CVE-2026-21627 | lab `labs/cve-2026-21627` (nrframework via Convert Forms 5.0.4) | safe access control | NOT_YET_VALIDATED | — |
| CVE-2026-48907 | JCE 2.9.99.x archives retained | safe upload route | NOT_YET_VALIDATED | — |
| CVE-2026-48908 | SP Page Builder 6.0.0 (Joomla 5.4.9) | aggressive icon-package upload + `.htaccess`/non-PHP RCE | CONFIRMED | 3.8.9 NOT_CONFIRMED (no handler); 6.10.0 PATCHED (403) |
| CVE-2026-48939 | iCagenda 3.7.21 archive retained | aggressive upload | NOT_YET_VALIDATED | — |
| CVE-2026-49049 | Helix3 2.2 archive retained | safe/aggressive AJAX handler | NOT_YET_VALIDATED | — |
| CVE-2026-56290 | Page Builder CK (ambiguous 1.x/2.x/3.x range) | aggressive upload | NOT_YET_VALIDATED (needs exact PoC-confirmed archive) | — |
| CVE-2026-56291 | Balbooa Forms 2.4.3.1/2.4.4.0 | aggressive upload (forced) | PATCHED (both; source already has `checkToken`) | 2.4.0 BLOCKED_EXTERNAL (no archive) |
| CVE-2026-56292 | — | safe SQLi | NOT_YET_VALIDATED | — |
| CVE-2026-57827 | RSFiles 1.16.29 | aggressive session-warmed upload + RCE | CONFIRMED | 1.17.12 BLOCKED_EXTERNAL (no archive) |
| CVE-2026-57829 | Helix Ultimate 1.1.4/2.2.4 archives retained | safe stored XSS | NOT_YET_VALIDATED | — |
| CVE-2026-57830 | Helix Ultimate 2.2.4/2.2.6 | safe file deletion (disposable files) | NOT_YET_VALIDATED | — |
| CVE-2026-71573 | — | safe CORS origin validation | NOT_YET_VALIDATED | — |
| CVE-2026-73373 | Joomla 5.4.7 package retained | safe SHTML upload (needs upload surface; Convert Forms field usable) | NOT_YET_VALIDATED | — |
| CVE-2026-78079 | Helix Ultimate 1.0-2.2.9 archives retained | safe open redirect | NOT_YET_VALIDATED | — |
| CVE-2026-90915 | Joomla 5.4.8 | aggressive canary directory deletion via cache purge | CONFIRMED | 5.4.9 NOT_CONFIRMED (HTTP 500, canary intact) |
| CVE-2026-94132 | — | safe mailbox attachment RCE vector | NOT_YET_VALIDATED | — |

## Joomla — passive-only (out of contract scope; tracked for sourcing)

| CVE | Note |
|---|---|
| CVE-2025-26854 (Articles Good Search) | BLOCKED_EXTERNAL: needs 1.2.4.0011 package. |
| CVE-2026-61424 (DJ-Classifieds) | BLOCKED_EXTERNAL: local `dj_classifieds_3.11` archive is data exports only, not an installable extension; needs complete 3.11.1. |
| CVE-2026-92222 (core SSRF) | No active proof: JSST advisory names no endpoint/parameter and 5.4.8→5.4.9 shows broad hardening; CVE requires high privileges. |

## Generic web libraries — active probes

| CVE | Fixture | Probe | Disposition | Patched control |
|---|---|---|---|---|
| CVE-2018-9206 | lab `labs/cve-2018-9206` (blueimp v9.22.0) | safe upload | NOT_YET_VALIDATED | — |
| CVE-2021-23394 | elFinder tags retained | safe upload | NOT_YET_VALIDATED | — |
| CVE-2026-111497 | — | safe node2shell | NOT_YET_VALIDATED | — |
| CVE-2026-81891 | lab `labs/cve-2026-81891` (elFinder 2.1.69/2.1.70) | safe text-only `.phtml` differential (direct upload must fail, ZIP extraction tested) | NOT_YET_VALIDATED | — |

## PHP runtimes — active probes

| CVE | Fixture | Probe | Disposition | Patched control |
|---|---|---|---|---|
| CVE-2012-1823 | PHP-CGI historical fixture per REQUIREMENTS | safe | NOT_YET_VALIDATED | — |
| CVE-2024-4577 | Windows PHP-CGI lab per REQUIREMENTS | safe | NOT_YET_VALIDATED (needs Windows VM/container host) | — |
