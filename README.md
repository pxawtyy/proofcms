# ProofCMS

ProofCMS is a modular Python toolkit for detecting content management systems and validating known vulnerabilities with explicit evidence, false-positive controls, and CI-friendly reports.

The current release detects Joomla and WordPress and includes vulnerability checks for both CMS families.

> [!CAUTION]
> Run ProofCMS only against systems you own or are explicitly authorized to test. Active verification is disabled by default and requires explicit authorization flags.

## Features

- Independent Joomla and WordPress fingerprinting
- Native Python Joomla discovery with no Perl or external scanner dependency
- Baseline probes that reject custom-200 pages, blanket-403 responses, and redirects to the home page
- Strict Joomla manifest validation
- PEP 440-aware version comparisons, including correct pre-release handling
- Passive, safe, and isolated-lab verification modes
- Runtime evidence that distinguishes successful PHP execution from source-code disclosure
- Per-module error isolation
- Proxy-aware HTTP transport
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

## Implemented vulnerability checks

| CVE | Component | Affected rule | Verification modes |
|---|---|---|---|
| `CVE-2010-4166` | Joomla `com_weblinks` | Joomla 1.5.x through 1.5.21 | `safe` |
| `CVE-2015-8562` | Joomla core | Joomla 1.5.x, 2.x, and 3.x before 3.4.6 | `aggressive` |
| `CVE-2026-48907` | JCE Editor | Before 2.9.99.5 | `safe` |
| `CVE-2026-48908` | SP Page Builder | 1.0.0 through 6.6.1 | `aggressive` |
| `CVE-2026-48939` | iCagenda | 3.2.1–3.9.14 and 4.0.0–4.0.7 | `aggressive` |
| `CVE-2026-49049` | Helix3 | 1.0 through 3.1.0 | `safe`, `aggressive` |
| `CVE-2026-56290` | Page Builder CK | Public affected range remains ambiguous | `aggressive` |
| `CVE-2026-56291` | Balbooa Forms | Through 2.4.0 | `aggressive` |
| `CVE-2026-57827` | RSFiles! | Before 1.17.12 | `aggressive` |
| `CVE-2026-57830` | Helix Ultimate | Through 2.2.6 | `safe` |
| `CVE-2026-32475` | Elementor Pro | Through 4.2.1 | `safe` |
| `CVE-2026-60137` | WordPress core | 6.8.0–6.8.5, 6.9.0–6.9.4, and 7.0.0–7.0.1 | `safe` |
| `CVE-2026-63030` | WordPress core | 6.9.0–6.9.4 and 7.0.0–7.0.1 | `safe` |
| `CVE-2026-87902` | WordPress core | Branch-specific ranges from 4.7.0 through 7.1.1 | `safe` |

An ambiguous or unavailable version produces an inconclusive result instead of an unsupported vulnerability claim.

## Joomla component inventory

Every Joomla scan checks public manifests and front-end component routes for commonly deployed extensions. The inventory currently includes Akeeba Backup (current `com_akeebabackup` and legacy `com_akeeba`), JSitemap, JCE, Convert Forms, RSForm! Pro, Event Booking, and EngageBox, in addition to components required by vulnerability modules. Detection requires extension-specific content; a generic HTTP `200` response is rejected.

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
├── core/                 # HTTP, evidence, models, probes, and versions
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

## Development

Isolated, loopback-only WordPress reproduction environments are available under
[`labs/`](labs/).

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

Run static checks:

```bash
python -m ruff check .
python -m mypy proofcms
```

GitHub Actions runs Ruff, the tests, and CLI smoke checks on Python 3.10, 3.11, and 3.12.

## Credits

ProofCMS's native Python Joomla discovery is inspired by the work of [OWASP JoomScan](https://github.com/OWASP/joomscan). ProofCMS does not bundle or execute JoomScan's Perl implementation and does not require JoomScan to be installed.

## License

Released under the [MIT License](LICENSE).
