# ProofCMS

ProofCMS is a modular Python toolkit for detecting content management systems and validating known vulnerabilities with explicit evidence, false-positive controls, and CI-friendly reports.

The current release detects Joomla and WordPress, includes vulnerability checks for both CMS families,
and separately fingerprints the web-facing PHP runtime.

> [!CAUTION]
> Run ProofCMS only against systems you own or are explicitly authorized to test. Active verification is disabled by default and requires explicit authorization flags.

## Features

- Independent Joomla and WordPress fingerprinting
- PHP runtime fingerprinting from public response headers and error output
- Native Python Joomla discovery with no Perl or external scanner dependency
- Baseline probes that reject custom-200 pages, blanket-403 responses, and redirects to the home page
- Strict Joomla manifest validation
- PEP 440-aware version comparisons, including correct pre-release handling
- Passive, safe, and isolated-lab verification modes
- Runtime evidence that distinguishes successful PHP execution from source-code disclosure
- Per-module error isolation
- Proxy-aware HTTP transport
- Verified TLS by default, with an explicit `--insecure` lab override
- Concurrent Joomla component inventory with on-demand vulnerability-specific detectors
- Console, JSON, and timestamped text reports
- CI-oriented exit codes

## Requirements

- Python 3.10 or newer
- `requests>=2.28.0`
- `packaging>=21.0`

## Installation

```bash
git clone https://github.com/pxawtyy/proofcms.git
cd proofcms
python -m pip install -e .
```

This installs the `proofcms` command. The package can also be invoked directly with `python -m proofcms`.

Install the development tools with:

```bash
python -m pip install -e ".[dev]"
```

## Quick start

Detect the CMS and run passive checks:

```bash
proofcms -u https://example.test
```

Force a CMS detector:

```bash
proofcms -u https://example.test --cms joomla
proofcms -u https://example.test --cms wordpress
```

Scan targets from a file:

```bash
proofcms -l targets.txt
```

Targets must be HTTP(S) application roots or CMS subdirectories. Query strings and fragments are rejected. TLS
certificates are verified by default; use `--insecure` only for isolated lab targets with self-signed certificates.

Select one or more CVEs:

```bash
proofcms -u https://example.test --cve CVE-2026-48907,CVE-2026-48939
```

List all registered checks:

```bash
proofcms --list-cves
```

## Verification modes

Active verification runs only when requested with `--run-exploit` and acknowledged with the required authorization flags.

| Mode | Behavior | Required acknowledgement |
|---|---|---|
| `safe` | Uses the lowest-impact proof implemented by the selected check. | `--i-understand-authorized` |
| `aggressive` | Uses upload, state-changing, or controlled RCE proof intended for isolated labs. | `--i-understand-authorized --i-understand-lab-only` |
| `auto` | Prefers `safe`; uses `aggressive` only when no safe proof exists. | Depends on the effective mode |

Example safe verification:

```bash
proofcms -u https://lab.example.test \
  --cve CVE-2010-4166 \
  --run-exploit CVE-2010-4166 \
  --exploit-mode safe \
  --i-understand-authorized
```

Run all aggressive lab probes:

```bash
proofcms -u https://lab.example.test \
  --run-all-lab-probes \
  --i-understand-authorized \
  --i-understand-lab-only
```

Run the legacy Joomla proofs individually. CVE-2015-8562 uses `uname -a` by default; pass
`--aggressive-command` only when a different lab command is needed:

```bash
proofcms -u http://127.0.0.1:8081 --cms joomla \
  --cve CVE-2015-8562 --run-exploit CVE-2015-8562 \
  --exploit-mode aggressive \
  --i-understand-authorized --i-understand-lab-only

proofcms -u http://joomla-3-8-11.lab --cms joomla \
  --cve CVE-2018-15882 --run-exploit CVE-2018-15882 \
  --exploit-mode aggressive \
  --i-understand-authorized --i-understand-lab-only
```

Plain `http://` targets are supported. ProofCMS uses direct transport by
default instead of inheriting machine-wide proxy settings; pass `--proxy`
when the authorized target must be reached through an explicit proxy.
If an HTTP target redirects to HTTPS with an expired or self-signed
certificate, TLS verification will fail by design; use `--insecure` only in
an isolated, authorized lab where bypassing certificate validation is safe.

### Designing proofs: prefer non-mutating differentials

Reflection alone never proves evaluation. A marker echoed back verbatim may
simply have been reflected, so new probes must demonstrate that the server
*acted* on the input — without writing files or changing state when a
differential allows it:

- **Known-output differential.** Submit a registered construct whose handler
  renders fixed, observable output (e.g. a self-evaluating shortcode with no
  attributes) and require both the marker and the handler output in the
  response. `proofcms.core.differential.confirm_shortcode_output` implements
  this; CVE-2026-92229 is the reference user.
- **Validation-error differential.** Submit input that only a trusted code
  path validates, and key the verdict on a field-specific validation error
  (CVE-2026-15748: the forged upload field is rejected while an identical
  baseline is processed normally). Nothing is written.
- **Do not claim evaluation from reflection.** A public Forminator PoC treated
  a reflected marker as exploitation even though `esc_url()` had already
  percent-encoded the brackets, so no shortcode could parse. Require handler
  output or a behavioral difference instead.

## Implemented vulnerability checks

| CVE | Component | Affected rule | Verification modes |
|---|---|---|---|
| `CVE-2012-1823` | PHP-CGI runtime | Before 5.3.13 and 5.4.0–5.4.2 | `safe` |
| `CVE-2019-11043` | PHP-FPM with Nginx | Affected PHP 7.1–7.3 branches with vulnerable PATH_INFO configuration | passive |
| `CVE-2024-4577` | PHP-CGI on Windows | Unsupported branches and affected PHP 8.1–8.3 releases | `safe` |
| `CVE-2018-9206` | Blueimp jQuery File Upload sample handler | Through 9.22.0 with public PHP handler | `safe` |
| `CVE-2021-23394` | elFinder | Before 2.1.58 | `safe` |
| `CVE-2026-81891` | elFinder ZIP extraction | Before 2.1.70 | `safe` |
| `CVE-2026-42945` | NGINX rewrite module | 0.6.27–1.30.0 with vulnerable rewrite configuration | passive |
| `CVE-2026-42530` | NGINX HTTP/3 module | 1.31.0–1.31.1 with HTTP/3 enabled | passive |
| `CVE-2026-42055` | NGINX proxy-v2 / gRPC modules | Branch-specific releases before 1.30.3 / 1.31.2 | passive |
| `CVE-2026-9256` | NGINX rewrite module | Branch-specific releases before 1.30.2 / 1.31.1 | passive |
| `CVE-2026-111497` | Node.js bundled Brotli decoder (Node2Shell) | Node 22.x <22.23.4, 24.x <24.22.1, 26.x <26.12.1, and EOL lines | `safe` differential |
| `CVE-2020-35489` | Contact Form 7 | Before 5.3.2 | passive |
| `CVE-2020-25213` | WP File Manager | 6.0–6.8 | passive |
| `CVE-2023-28121` | WooPayments | Branch-specific unpatched releases from 4.8.0 | `safe` |
| `CVE-2023-32243` | Essential Addons for Elementor | 5.4.0–5.7.1 | passive |
| `CVE-2023-3460` | Ultimate Member | Before 2.6.7 | passive |
| `CVE-2024-10924` | Really Simple Security | 9.0.0–9.1.1.1 | passive |
| `CVE-2024-28000` | LiteSpeed Cache | 1.9–6.3.0.1 | passive |
| `CVE-2024-6220` | Keydatas | Through 2.5.2 | passive |
| `CVE-2010-4166` | Joomla `com_weblinks` | Joomla 1.5.x through 1.5.21 | `safe` |
| `CVE-2015-8562` | Joomla core | Joomla 1.5.x, 2.x, and 3.x before 3.4.6 | `aggressive` |
| `CVE-2015-7297` | Joomla core content history | Joomla 3.2.0-3.4.4 | `safe` error-based differential |
| `CVE-2015-7857` | Joomla core content history | Joomla 3.2.0-3.4.4 | `safe` SQL-error differential |
| `CVE-2015-7858` | Joomla core content history | Joomla 3.2.0-3.4.4 | `safe` POST subquery differential |
| `CVE-2016-8869` | Joomla registration privileges | Joomla 3.4.4–3.6.3 | `aggressive` account creation |
| `CVE-2016-8870` | Joomla disabled-registration account creation | Joomla 3.4.4–3.6.3 | `aggressive` account creation |
| `CVE-2017-8917` | Joomla core `com_fields` | Joomla 3.7.0 | passive |
| `CVE-2018-15882` | Joomla core `InputFilter` | Before 3.8.12 | `aggressive` inert PHAR-stub upload |
| `CVE-2024-40744` | Convert Forms | Before 4.4.8 | `safe` |
| `CVE-2025-26854` | Articles Good Search | 1.0.0–1.2.4.0011 | passive |
| `CVE-2026-21627` | Novarain/Tassos Framework and bundled extensions | Framework 4.10.14–6.0.37; product-specific ranges | `safe` |
| `CVE-2026-48907` | JCE Editor | Before 2.9.99.5 | `safe` |
| `CVE-2026-48908` | SP Page Builder | 1.0.0 through 6.6.1 | `aggressive` |
| `CVE-2026-48939` | iCagenda | 3.2.1–3.9.14 and 4.0.0–4.0.7 | `aggressive` |
| `CVE-2026-49049` | Helix3 | 1.0 through 3.1.0 | `safe`, `aggressive` |
| `CVE-2026-56290` | Page Builder CK | Public affected range remains ambiguous | `aggressive` |
| `CVE-2026-56291` | Balbooa Forms | Through 2.4.0 | `aggressive` |
| `CVE-2026-57827` | RSFiles! | Before 1.17.12 | `aggressive` |
| `CVE-2026-57830` | Helix Ultimate arbitrary file deletion | Through 2.2.6 | `safe` |
| `CVE-2026-57829` | Helix Ultimate unauthenticated stored XSS | 1.0–2.2.6 | `safe` precondition probe |
| `CVE-2026-102426` | SP Page Builder Dynamic Content Filter reflected XSS | 3.0.0–5.6.1p2 | `safe` marker probe |
| `CVE-2026-61424` | DJ-Classifieds arbitrary file upload | Before 3.11.2 | passive |
| `CVE-2026-71573` | Joomla core CORS origin validation | Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2; CORS enabled | `safe` preflight + credentialed reflection check |
| `CVE-2026-72531` | Joomla core `com_fields` API ACL | Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 | `aggressive` field creation |
| `CVE-2026-73373` | Joomla core SHTML upload | 1.0.0-5.4.7 and 6.0.0-6.1.2 | `safe` |
| `CVE-2026-78079` | Helix Ultimate open redirect | Through 2.2.9 | `safe` authenticated `helixreturn` check |
| `CVE-2026-90915` | Joomla cache purge | Joomla 4.0.0–5.4.8 and 6.0.0–6.1.3 | passive |
| `CVE-2026-92222` | Joomla core extensions SSRF | Joomla 4.0.0–5.4.8 and 6.0.0–6.1.3; PR:H required | passive (not confirmed without high-privilege evidence) |
| `CVE-2026-56292` | AcyMailing SQL injection | 1.0–10.11.0 | `safe` constant-only differential |
| `CVE-2026-94132` | AcyMailing Enterprise mailbox attachment RCE | 1.0.0-11.0.5 | lab-confirmed full email→cron→PHP execution; module probe is a read-only companion |
| `CVE-2026-32475` | Elementor Pro | Through 4.2.1 | `safe` |
| `CVE-2026-92229` | Forminator shortcode execution | Through 1.57.2 | `safe` harmless shortcode proof |
| `CVE-2026-15748` | Forminator select/file upload injection | 1.18.1–1.56.1 | `safe` precondition probe |
| `CVE-2024-10402` | Forminator missing authorization | Through 1.35.1 | `safe` blocked without contributor session |
| `CVE-2026-6692` | Slider Revolution | 7.0.0–7.0.10 | passive |
| `CVE-2026-18781` | Drag and Drop Multiple File Upload for CF7 | Before 1.3.9.9 | passive |
| `CVE-2026-60137` | WordPress core | 6.8.0–6.8.5, 6.9.0–6.9.4, and 7.0.0–7.0.1 | `safe` |
| `CVE-2018-8284` | .NET Framework remote code injection | Legacy .NET Framework branches; OS/build prerequisites required | passive |
| `CVE-2023-21722` | .NET Framework denial of service | Legacy .NET Framework branches; exact servicing build required | passive |
| `CVE-2023-36560` | ASP.NET security feature bypass | Legacy .NET Framework branches; exact servicing build required | passive |
| `CVE-2023-36899` | ASP.NET elevation of privilege | IIS/.NET Framework branches; app-pool and OS prerequisites required | passive |
| `CVE-2026-63030` | WordPress core | 6.9.0–6.9.4 and 7.0.0–7.0.1 | `safe` |
| `CVE-2026-87902` | WordPress core | Branch-specific ranges from 4.7.0 through 7.1.1 | `safe` |
| `CVE-2024-4439` | WordPress core Avatar block stored XSS | 6.0.x–6.5.1 (branch-specific backports) | passive advisory + documented PoC |
| `CVE-2026-64638` | WordPress core login reflected XSS | 4.7.x-7.0.2 (branch-specific backports) | `safe` parser-differential reflection |
| `WPVDB-df1ca42d-b835-4ed6-a634-3f62ac020e77` | WordPress core comment-moderation stored XSS | branch-specific WPScan ranges | passive advisory |
| `WPVDB-aa354358-3a32-4e81-8628-d1aa917b5efa` | WordPress core comment stored XSS | branch-specific WPScan ranges | passive advisory |
| `WPVDB-5e9804e5-bbd4-4836-a5f0-b4388cc39225` | WordPress core insecure deserialization | branch-specific WPScan ranges | passive advisory |

The three `WPVDB-*` identifiers are WPScan database IDs because the source
advisories do not publish assigned CVE numbers. They are intentionally kept
distinct from CVE records instead of using fabricated identifiers. The
Avatar-block PoC is recorded as metadata but is never sent automatically.

An ambiguous or unavailable version produces an inconclusive result instead of an unsupported vulnerability claim.

## Joomla component inventory

Every Joomla scan checks public manifests and front-end component routes for commonly deployed extensions. The inventory includes AcyMailing, Akeeba extensions, JSitemap, JCE, K2, Convert Forms and its add-ons, Dropfiles, RSForm! Pro add-ons, Event Booking, EngageBox, Smart Slider 3, SP Page Builder extensions, and Tassos GeoIP, in addition to components required by vulnerability modules. Detection requires extension-specific content; a generic HTTP `200` response is rejected.

Use `--inventory required` for narrow scans that should run only component detectors required by the selected CVEs.
The default `--inventory full` preserves the complete Joomla inventory.

To keep large scans readable, `PATCHED`, `NOT_DETECTED`, and `NOT_AFFECTED` CVEs and undetected plugin inventory entries are hidden by default. Use `--show-patched` or `--show-not-detected` for their respective categories, or `--show-all` to disable every display filter. JSON reports retain every result regardless of terminal filtering.

## Named attack chains

ProofCMS keeps vulnerability nicknames separate from official CVE identifiers.
The `wp2shell` chain combines `CVE-2026-63030` with `CVE-2026-60137`:

```bash
# Passive assessment of both prerequisites
proofcms -u https://lab.example.test --cms wordpress --chain wp2shell

# Safe confirmation of the combined nested-batch timing path
proofcms -u https://lab.example.test \
  --cms wordpress \
  --chain wp2shell \
  --run-exploit all \
  --exploit-mode safe \
  --i-understand-authorized
```

Chain findings have their own `chains` collection in JSON reports and their own
report section. The safe proof does not run the wp2shell RCE stage, extract data,
write to the database, create accounts, or upload files.

## Result states

Every result also includes a human-readable `vulnerability_type` in console, text, and JSON output.
The normalized taxonomy includes SQL Injection, Unrestricted File Upload, Authentication Bypass,
Privilege Escalation, Improper Access Control, Path Traversal, SSRF, XSS, Open Redirect, Object
Injection, Argument Injection, Memory Corruption, Remote Code Execution, and Exposed Attack Surface.
New modules may set `vulnerability_type` explicitly in their metadata and findings; otherwise
ProofCMS derives it from the CVE identifier and module name and verifies that registered modules do
not fall back to `Other`.

| State | Meaning |
|---|---|
| `NOT_DETECTED` | No reliable public evidence of the component was found. |
| `DETECTED_VERSION_UNKNOWN` / `INCONCLUSIVE` | The component was detected, but applicability could not be established. |
| `NOT_AFFECTED` | The detected component is outside the affected range. |
| `PATCHED` | The detected version is at or above a documented fix. |
| `LIKELY_VULNERABLE` | The detected version is in the affected range without active proof. |
| `VULNERABLE` | Runtime evidence confirmed the reported impact. |
| `VULNERABLE_UPLOAD_ONLY` | A file write was confirmed, but execution was not. |
| `NOT_CONFIRMED` | A requested proof did not confirm the vulnerability. |
| `ERROR` | A check failed without stopping the remaining scan. |

## Reports and CI

Write a JSON report:

```bash
proofcms -u https://example.test --json results.json
```

JSON creation is atomic and refuses to overwrite an existing file. Pass `--overwrite-json` when replacement is
intentional. Report output redacts URL credentials and common sensitive query parameters.

Text reports are written to `reports/proofcms_<timestamp>_<run-id>.txt` unless `--no-text-report` is used. Proxy credentials, commands, tokens, and other sensitive command-line values are redacted from text reports.

Use `--fail-on` to integrate results into a pipeline:

```bash
proofcms -u https://staging.example.test --fail-on vulnerable,error
```

| Exit code | Meaning |
|---|---|
| `0` | Scan completed without a configured failure condition. |
| `1` | CLI syntax or operational failure. |
| `2` | Confirmed vulnerability matched `--fail-on`. |
| `3` | Likely vulnerability matched `--fail-on`. |
| `4` | Inconclusive result matched `--fail-on`. |
| `5` | Module error matched `--fail-on`. |

## Architecture

```text
proofcms/
├── core/                 # HTTP, evidence, models, vulnerability categories, probes, and versions
├── detectors/            # Independent Joomla and WordPress discovery
├── modules/
│   ├── base.py           # VulnerabilityModule protocol
│   ├── joomla/           # Joomla core and extension checks
│   └── wordpress/        # WordPress check namespace
├── reporting/            # Console, JSON, and text output
├── cli.py                # Command-line orchestration
└── __main__.py           # python -m proofcms entry point
```

New vulnerability logic belongs under `proofcms/modules/<cms>/`. Shared HTTP, version, evidence, and probe behavior belongs under `proofcms/core/`.

## Shared framework (do not re-implement per module)

Five patterns used to be copy-pasted across modules; they live in core now:

- **Authenticated sessions** (`proofcms/core/auth.py`): `joomla_admin_login` /
  `verify_joomla_admin_login` and `wordpress_admin_login`. Module-level
  `admin_login` / `verify_admin_login` wrappers stay as thin delegates so
  existing tests keep patching the same names.
- **Page discovery** (`proofcms/core/crawl.py`): `crawl_pages` (seed paths +
  same-site homepage `href` crawl) and `rest_list_links` (`?rest_route=`
  listings). HTML field parsers stay in their modules.
- **Named aggressive arguments** (`proofcms/core/args.py`): repeatable
  `--aggressive-arg KEY=VALUE`, parsed once in the CLI and handed to every
  `check()` as the `aggressive_args` mapping. New probes read named keys;
  legacy `--aggressive-command` strings keep working as a fallback.
  Document the keys in the `--aggressive-arg` help and the lab README.
- **Proof transcripts** (`proofcms/core/transcript.py`): `HttpClient`
  records a lightweight entry (method, scrubbed URLs, status, body hash)
  per exchange, and the stateless `request()` helper keeps a thread-local
  ring. Attach the tail via `attach_transcript(evidence, sess)` or
  `take_transcript()` when building a `VULNERABLE` finding so reports
  carry comparable request/response pairs. Bodies are never stored.
- **Lab cleanup** (`proofcms/core/cleanup.py` + `proofcms --lab-cleanup CVE`):
  modules that create artifacts expose `cleanup(target_url, *, timeout,
  proxy, aggressive_args, aggressive_command)` returning `cleanup_result()`
  (`removed` / `remaining` / `manual`). Prefer exact IDs from the probe
  report (`file_hash`, `folder`/`file`/`token`), fall back to sweeping the
  module's known `proofcms-*` patterns, and always report dotfiles and
  folders HTTP cannot delete as `manual` shell steps. `proofcms --lab-cleanup`
  lists modules with hooks when the CVE has none.

## Development

Isolated, loopback-only WordPress reproduction environments are available under
[`labs/`](labs/).

> **AI agents:** read [`.agents/AGENTS.md`](.agents/AGENTS.md) first. It holds
> the repo conventions (loopback-only labs, validation-matrix rules, shared
> framework, Windows/Docker gotchas) plus an index of the focused guides.

Use one Python environment for everything. The `[dev]` extra is the single
source of dev tooling (pytest, ruff, mypy):

```bash
python -m pip install -e ".[dev]"
```

Install the pre-commit hooks so lint and whitespace issues are caught before
push (CI runs the same checks and will fail otherwise):

```bash
pip install pre-commit
pre-commit install
```

Run the complete test suite:

```bash
python -m pytest
```

Run static checks:

```bash
python -m ruff check .
python -m mypy proofcms
```

GitHub Actions runs Ruff, the tests, and CLI smoke checks on Python 3.10, 3.11, and 3.12.

Line endings are normalized to LF on commit via `.gitattributes`; do not
commit CRLF conversions as content changes.

Every module that advertises active exploit modes (`exploit_modes` non-empty
in its `metadata()`) must have unit tests referencing it and a disposition row
in [`labs/VALIDATED.md`](labs/VALIDATED.md), and every registered check must
have a row there (passive-only modules link to what blocks active proof).
`tests/test_module_contract.py` enforces all three; add the row (CONFIRMED,
NOT_CONFIRMED, BLOCKED_EXTERNAL, or NOT_YET_VALIDATED with the reason, plus
the lab directory and validation date/commit for CONFIRMED runs) in the same
commit as the module.

## Credits

ProofCMS's native Python Joomla discovery is inspired by the work of [OWASP JoomScan](https://github.com/OWASP/joomscan). ProofCMS does not bundle or execute JoomScan's Perl implementation and does not require JoomScan to be installed.

## License

Released under the [MIT License](LICENSE).
