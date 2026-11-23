# Frontier-model review triage (2026-11-23)

A sanitized 35-file packet was reviewed by an external model. Paths and
identifiers were rewritten (`framework/` -> `proofcms/`) but line numbers were
preserved. This note records which findings reproduce in the real repository,
which were sanitization artifacts, and what changed. Target-specific evidence
stays in the gitignored `reports/` tree.

## Verdicts

| ID | Verdict | Notes |
|---|---|---|
| D-01 | **Real, fixed** | `/phpinfo.php` origin probing is now opt-in (`--probe-disclosed-origin`) and no longer forces `verify_tls=False`; it follows the global `--insecure` policy. |
| D-02 | **Real, fixed** | Redirects now reject non-HTTP(S) schemes and public-to-private pivots; secondary fetches in the ASP.NET, GeneXus and REST crawlers are same-site only. |
| D-03 | **Real, fixed** | Redaction is centralized in `core/redact.py`: URL userinfo, fragments, composite/`set-cookie`/session keys, non-HTTP proxy URLs, transcripts, console/text/diff output and `allow_abbrev=False`. |
| D-04 | **Real, fixed** | Text fallback uses a unique `mkdtemp` directory and atomic exclusive writes; JSON's hard-link fallback uses `O_EXCL` instead of `exists()` + `replace()`. |
| D-05 | **Artifact** | The real CLI uses `--run-exploit`/`--exploit-mode` and reads `args.run_exploit`/`args.exploit_mode`; the packet's `run-impact` names were a lexical substitution. No code change. |
| D-06 | **Real, fixed** | Discovery-cache keys include `follow_redirects` and user agent, cache is disabled for cookie-bearing clients, cached dicts are deep-copied, the enabled flag is read under the lock, and thread-local sessions are closed. |
| D-07 | **Real, fixed** | Multipart boundaries use `secrets.token_bytes` with collision checks; CR/LF in names/filenames/content types is rejected; quotes are escaped and non-Latin-1 filenames use RFC 5987. |
| D-08 | **Real, fixed** | `version_in_specifier` evaluates prereleases (`prereleases=True`), so `1.5.21-rc1` matches `<=1.5.21`. |
| D-09 | **Real, mostly fixed** | `--rate-limit` rejects negative/NaN/inf; `--diff` validates the JSON object and counts failures; `--sarif` respects `--overwrite-sarif` and counts write failures; `selection_needs_lab` tolerates unloadable modules. Optional-probe `except Exception` blocks remain intentionally quiet. |
| D-10 | **Real, fixed** | Target-specific codenames/vendor builds were removed from tracked code and moved to an optional, gitignored `.redaction-local.json`; `reports/` and `logs/` are no longer skipped if force-tracked. |
| D-11 | **Real, fixed** | Gridbox login verifies the response and reuses `core.auth`; WordPress login checks same-origin and language-independent admin markers; the shortcode differential requires the sink reflection; category lookup is case-insensitive; Node requires a `node` token; NGINX ignores version text in HTML and rate-limits the ALPN probe. |
| D-12 | **Real, partly artifact** | The key is `executionSuccessful` in the real code (the packet's `effectSuccessful` was sanitized), but the fixed `True` was real. It is now computed from `modules_setup_failed` and `summary_by_status["ERROR"]`, and `build_sarif_report` redacts internally. |

## Behavior changes to note

- `--sarif` no longer overwrites an existing file unless `--overwrite-sarif` is
  passed.
- PHP origin probing is off by default; use `--probe-disclosed-origin` on an
  authorized lab. TLS verification still follows the global policy.
- Redirects from a public target to a loopback/private/link-local address are
  rejected. Lab targets that start on a private address may still redirect
  within that private network.
- NGINX and Node detection now require header/banner evidence instead of
  matching version-shaped text in arbitrary HTML.

## Validation

`python tools/verify.py` passes: 1166 tests, the module contract, and mypy.
`python -m proofcms.redaction --all` is clean.
