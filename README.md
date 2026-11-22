# ProofCMS

ProofCMS is a modular Python toolkit for detecting CMS platforms and validating
known vulnerabilities with explicit evidence, false-positive controls, and
CI-friendly reports.

It fingerprints Joomla, WordPress, the PHP runtime, Node.js, and ASP.NET/.NET
surfaces, and ships both passive checks and isolated-lab proof modules.

> [!CAUTION]
> Run ProofCMS only against systems you own or are explicitly authorized to
> test. Active verification is disabled by default and requires explicit
> authorization flags.

## Highlights

- Independent Joomla and WordPress fingerprinting, plus PHP, Node.js, and
  ASP.NET/.NET surface detection
- Baseline probes that reject custom-200 pages, blanket-403 responses, and
  redirects to the home page
- PEP 440-aware version comparisons, including pre-release handling
- Passive, safe, and isolated-lab verification modes
- Runtime evidence that distinguishes code execution from source disclosure
- Proxy-aware HTTP transport, verified TLS by default, explicit `--insecure`
  lab override
- Concurrent Joomla component inventory with vulnerability-specific detectors
- Console, JSON, and timestamped text reports with CI-oriented exit codes

## Documentation

- [CVE index](docs/CVE-INDEX.md) — every registered check, grouped by family
- [Module contract](docs/MODULE_CONTRACT.md) — evidence rules, shared framework, proof design
- [Validation matrix](labs/VALIDATED.md) — fixtures, probes, controls, and dispositions
- [Ruby2Shell inventory](docs/RUBY2SHELL.md) — local Ruby version check and primitive lab
- [Windows lab notes](docs/WINDOWS-LAB.md) — Windows-only checks and their prerequisites
- [Contributing](CONTRIBUTING.md) — target-data rules, tests, and the validation-row recorder

## Critical checks

A curated subset of the highest-impact checks. The complete registry lives in
[`docs/CVE-INDEX.md`](docs/CVE-INDEX.md); the live list is `proofcms --list-cves`.

| Nickname / CVE | Component | Impact |
|---|---|---|
| Node2Shell / `CVE-2026-111497` | Node.js bundled Brotli decoder | Remote code execution |
| React2Shell / `CVE-2025-55182` | React Server Components / Next.js App Router | Remote code execution |
| RSC Flight typed-array desync / `CVE-2026-126187` | React Server Components / Next.js Cache Components | Remote code execution |
| Ruby2Shell / `CVE-2026-132825` | Ruby string case conversion (ISO-8859/Windows-125x) | Heap overflow; local primitive reproduced, RCE chain not public |
| PHP2Shell / `CVE-2026-109618` + `CVE-2026-109619` | PHP Zend Engine / request-shutdown memory corruption | Remote code execution |
| `CVE-2024-4577` | PHP-CGI on Windows | Remote code execution |
| `CVE-2025-53772` | IIS Web Deploy (msdeploy.axd) | Authenticated deserialization RCE |
| WP2Shell / `CVE-2026-63030` + `CVE-2026-60137` | WordPress core chain | Remote code execution |
| NGINX2Root / `CVE-2026-123007` + 4 more | NGINX HTTP/2, HTTP/3, resolver/mirror and mail proxy | Independent source-confirmed memory-safety defects; passive checks only |
| `CVE-2012-1823` | PHP-CGI query string | Remote code execution |
| `CVE-2019-11043` | PHP-FPM PATH_INFO underflow | Remote code execution |
| `CVE-2015-8562` | Joomla core | Remote code execution |
| `CVE-2016-8869` | Joomla registration privileges | Privilege escalation |
| `CVE-2023-6553` | Backup Migration (WordPress) | Remote code execution |
| `CVE-2024-27956` | WP Automatic | Unauthenticated SQL injection |
| `CVE-2024-28000` | LiteSpeed Cache | Privilege escalation |
| `CVE-2026-92229` | Forminator | Remote code execution |
| `CVE-2026-102785` | YOOtheme Pro | Remote code execution |
| `CVE-2026-102788` | Gridbox | Unauthenticated SQL injection |
| `CVE-2026-105604` | DJ-Classifieds | Unauthenticated SQL injection |
| `CVE-2026-117551` | jDownloads | Remote code execution |
| `CVE-2026-94132` | AcyMailing Enterprise | Remote code execution |
| `CVE-2026-48908` | SP Page Builder | Remote code execution |
| `CVE-2026-57829` | Helix Ultimate | Stored XSS |

### Additional Joomla checks

| CVE | Check | Affected rule | Mode |
|---|---|---|---|
| `CVE-2026-102425` | Balbooa Forms unauthenticated PHP-after-submission shortcode RCE | Balbooa Forms 1.0.0 through 2.4.3.3; fixed in 2.4.3.4 | `aggressive` |
| `CVE-2026-67364` | Balbooa Forms pre-auth PHP code injection via URL parameter shortcode | Balbooa Forms 1.0.0 through 2.4.3.1; fixed in 2.4.3.2 | `aggressive` |
| `CVE-2026-67365` | iCagenda calendar module unauthenticated SQL injection | iCagenda 4.0.0 through 4.0.11; fixed in 4.0.12 | `aggressive` |
| `CVE-2026-74254` | Page Builder CK styles model SQL injection | Page Builder CK 1.0.0 through 3.6.4; fixed in 3.6.5 | `aggressive` |
| `CVE-2026-77994` | Page Builder CK frontend loadStyles second-order SQL injection | Page Builder CK 1.0.0 through 3.6.4; fixed in 3.6.5 | `aggressive` |
| `CVE-2026-65880` | Balbooa Forms unauthenticated signature-field code execution | Balbooa Forms 1.0.0 through 2.4.3.1; fixed in 2.4.3.2 | `aggressive` |
| `CVE-2026-65766` | SP Page Builder Dynamic Content order SQL injection | SP Page Builder 1.0.0 through 6.7.0; fixed in 6.7.1 | `aggressive` |
| `CVE-2026-65876` | SP Page Builder loadMoreArticles catid SQL injection | SP Page Builder 1.0.0 through 6.7.0; fixed in 6.8.0 | `aggressive` |
| `CVE-2026-65879` | SP Page Builder hardcoded mail-relay secret | SP Page Builder 1.0.0 through 6.7.0; fixed in 6.7.1 | `passive` |
| `CVE-2026-67285` | SP Page Builder addon-name local PHP file inclusion | SP Page Builder 1.0.0 through 6.7.0; fixed in 6.8.0 | `aggressive` |
| `CVE-2025-30085` | RSForm! Pro authenticated submission-export remote code execution | RSForm! Pro 3.0.0 through 3.3.14; fixed in 3.3.15 | `aggressive` |
| `CVE-2026-66494` | SP Page Builder unauthenticated stored XSS in the Shapes API | SP Page Builder 1.0.0 through 6.6.1; fixed in 6.7.0 | `aggressive` |
| `CVE-2026-117543` | jDownloads external download URL redirect SSRF | jDownloads 1.0.0 through 4.1.7; fixed in 4.1.8 | `aggressive` |
| `CVE-2026-94130` | YouTube Gallery unauthenticated video-search SQL injection | YouTube Gallery 1.0.0 through 5.7.2; fixed in 5.7.3 | `aggressive` |
| `CVE-2026-48906` | Tassos Framework unauthenticated arbitrary file deletion | Tassos Framework 1.0.0 through 6.0.x; fixed in 6.1.0 | `aggressive` |
| `CVE-2026-94131` | AcyMailing custom file field arbitrary file deletion | AcyMailing 1.0.0 through 11.0.x; fixed in 11.1.0 | `aggressive` |
| `CVE-2026-78077` | Helix Ultimate stored XSS in Mega Menu layout values | Helix Ultimate 1.0.0 through 2.2.9; fixed in 2.2.10 | `aggressive` |
| `CVE-2026-78078` | Helix Ultimate privileged image-upload content-spoofing bypass | Helix Ultimate 1.0.0 through 2.2.9; fixed in 2.2.10 | `aggressive` |
| `CVE-2026-48941` | K2 unauthenticated gallery folder deletion | K2 1.0 through 2.26; fixed in 2.27 | `aggressive` |

Ruby2Shell is a local runtime inventory + lab (`tools/ruby2shell_check.py`,
`labs/cve-2026-132825`), not an HTTP CVE module. The lab confirms the one-byte
out-of-bounds write; the public RCE chain is not available yet.

Named chains keep their own report section. The `wp2shell` chain combines
`CVE-2026-63030` with `CVE-2026-60137`:

```bash
proofcms -u https://lab.example.test --cms wordpress --chain wp2shell
```

Additional chains aggregate primitives that are already exposed by separate
checks. They report composition exposure, not a replayed end-to-end exploit:

| Chain | Primitives | What it means |
|---|---|---|
| `phpinfo-to-origin-bypass` | `PROOFCMS-PHPINFO-EXPOSURE` + `PROOFCMS-ORIGIN-DIRECT-ACCESS` + `CVE-2019-11043`/`CVE-2024-4577` | phpinfo and direct-origin access expose the PHP-FPM/CGI RCE surface. |
| `joomla-session-to-upload` | `CVE-2026-90907` or `CVE-2026-48897` or `CVE-2026-92227` + `CVE-2026-105603` | A confirmed session-acquisition path plus the authenticated DJ-Classifieds avatar upload. |
| `joomla-token-to-upload` | `CVE-2026-21627` + `CVE-2026-105606` | A token-handling weakness plus a token-gated Custom Tables upload. |
| `nginx2root` | `CVE-2026-123007`, `CVE-2026-123634`, `CVE-2026-123633`, `CVE-2026-121810`, `CVE-2026-113425` | Five independent, configuration-dependent NGINX defects; portfolio exposure for patch prioritization, not a demonstrated chain. |

```bash
proofcms -u https://lab.example.test --cms joomla --chain joomla-session-to-upload
proofcms -u https://lab.example.test --cms joomla --chain joomla-token-to-upload
proofcms -u https://lab.example.test --chain phpinfo-to-origin-bypass
proofcms -u https://lab.example.test --chain nginx2root
```

The aggregates are conservative: they use `LIKELY_VULNERABLE` when the
prerequisites were confirmed independently but the chain itself was not run as
one session or one request sequence. A patched prerequisite makes the chain
`NOT_AFFECTED`. `nginx2root` is a portfolio aggregate of independent paths, so
it reports exposure for prioritization only and never claims a demonstrated
chain.

## Requirements

- Python 3.10 or newer
- `requests>=2.28.0`
- `packaging>=21.0`
- `cryptography>=41.0`

Optional: install `proofcms[http2]` (`h2>=4.0`) for the CVE-2026-70188 HTTP/2
trailer probe.

## Installation

```bash
git clone https://github.com/pxawtyy/proofcms.git
cd proofcms
python -m pip install -e .
```

This installs the `proofcms` command; `python -m proofcms` also works.

For development tooling (pytest, ruff, mypy):

```bash
python -m pip install -e ".[dev]"
```

## Quick start

Detect the CMS and run passive checks:

```bash
proofcms -u https://example.test
```

Force a CMS detector, scan a target file, or select specific CVEs:

```bash
proofcms -u https://example.test --cms joomla
proofcms -u https://example.test --cms wordpress
proofcms -l targets.txt
proofcms -u https://example.test --cve CVE-2026-48907,CVE-2026-48939
```

Targets must be HTTP(S) application roots or CMS subdirectories. Query strings
and fragments are rejected. TLS certificates are verified by default; use
`--insecure` only for isolated lab targets with self-signed certificates.

Plain `http://` targets are supported. ProofCMS uses direct transport by
default instead of inheriting machine-wide proxy settings; pass `--proxy` when
the authorized target must be reached through an explicit proxy.

## Verification modes

Active verification runs only when requested with `--run-exploit` and
acknowledged with the required authorization flags.

| Mode | Behavior | Required acknowledgement |
|---|---|---|
| `safe` | Lowest-impact proof implemented by the selected check. | `--i-understand-authorized` |
| `aggressive` | Upload, state-changing, or controlled RCE proof intended for isolated labs. | `--i-understand-authorized --i-understand-lab-only` |
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

Legacy Joomla proofs can still be run individually. CVE-2015-8562 uses
`uname -a` by default; pass `--aggressive-command` only when a different lab
command is needed. See [`labs/`](labs/) and
[`labs/VALIDATED.md`](labs/VALIDATED.md) for the fixtures.

## Result states

Every result includes a human-readable `vulnerability_type` in console, text,
and JSON output. New modules may set it explicitly; otherwise ProofCMS derives
it from the CVE identifier and module name and verifies that registered
modules do not fall back to `Other`.

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
| `BLOCKED_EXTERNAL` | A WAF/challenge page or missing external fixture prevented a definitive proof. |
| `ERROR` | A check failed without stopping the remaining scan. |

## Reports and CI

Write a JSON report (atomic; refuses to overwrite unless `--overwrite-json`):

```bash
proofcms -u https://example.test --json results.json
```

Text reports go to `reports/proofcms_<timestamp>_<run-id>.txt` unless
`--no-text-report` is used. Report output redacts URL credentials, common
sensitive query parameters, proxy credentials, commands, and tokens.

Export SARIF 2.1.0 for GitHub Security, DefectDojo, or another SARIF consumer:

```bash
proofcms -u https://example.test --sarif results.sarif
```

Compare a retest against a previous JSON report (prints only status/version
changes and suppresses the normal per-finding console output):

```bash
proofcms -u https://example.test --json retest.json --diff results.json
```

Limit outbound request rate and parallelize passive/safe modules:

```bash
proofcms -u https://example.test --rate-limit 10 --concurrency 5
```

`--rate-limit` is a process-wide token bucket in requests/second. `--concurrency`
applies to detector inventories and to passive or non-intrusive safe modules;
intrusive/aggressive probes still run serially.

Use `--fail-on` in a pipeline:

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

To keep large scans readable, `PATCHED`, `NOT_DETECTED`, and `NOT_AFFECTED`
results are hidden by default. Use `--show-patched`, `--show-not-detected`, or
`--show-all`; JSON reports retain every result regardless of terminal
filtering.

## Architecture

```text
proofcms/
├── core/                 # HTTP, transcript, cleanup, evidence, models, probes, versions
├── detectors/            # Independent Joomla, WordPress, and runtime discovery
├── modules/
│   ├── base.py           # VulnerabilityModule protocol
│   ├── generic/          # Runtime/product checks (ASP.NET, Node.js, elFinder, ...)
│   ├── joomla/           # Joomla core and extension checks
│   ├── php/              # PHP runtime checks
│   └── wordpress/        # WordPress core and plugin checks
├── chains/               # Named composite attack-chain aggregators
├── reporting/            # Console, JSON, text, diff, and SARIF output
├── redaction.py          # Output redaction for URLs, headers, and evidence
├── cli.py                # Command-line orchestration
└── __main__.py           # python -m proofcms entry point
```

New vulnerability logic belongs under `proofcms/modules/<cms>/`. Shared HTTP,
version, evidence, and probe behavior belongs under `proofcms/core/`. See
[`docs/MODULE_CONTRACT.md`](docs/MODULE_CONTRACT.md) for the module contract,
shared framework helpers, and proof-design rules.

## Development

Isolated, loopback-only reproduction environments live under [`labs/`](labs/).
The validation matrix is [`labs/VALIDATED.md`](labs/VALIDATED.md).

> **AI agents:** read [`.agents/AGENTS.md`](.agents/AGENTS.md) first. It holds
> the repo conventions (loopback-only labs, validation-matrix rules, shared
> framework, Windows/Docker gotchas) plus an index of focused guides.

Use one Python environment for everything. Install the dev extra and the
pre-commit hook so lint and whitespace issues are caught before push:

```bash
python -m pip install -e ".[dev]"
pip install pre-commit
pre-commit install
```

Run the complete suite and static checks:

```bash
python -m pytest
python -m ruff check .
python -m mypy proofcms
python -m proofcms.redaction --all
```

GitHub Actions runs Ruff, the tests, and CLI smoke checks on Python 3.10, 3.11,
and 3.12. Line endings are normalized to LF on commit via `.gitattributes`; do
not commit CRLF conversions as content changes.

Every module that advertises active exploit modes must have unit tests
referencing it and a disposition row in
[`labs/VALIDATED.md`](labs/VALIDATED.md); every registered check must have a
row there. `tests/test_module_contract.py` enforces both. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the validation-row recorder and the
target-data rules.

## Credits

ProofCMS's native Python Joomla discovery is inspired by the work of
[OWASP JoomScan](https://github.com/OWASP/joomscan). ProofCMS does not bundle or
execute JoomScan's Perl implementation and does not require JoomScan to be
installed.

## License

Released under the [MIT License](LICENSE).
