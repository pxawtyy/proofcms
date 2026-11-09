# Validation knowledge (item 1 — the biggest win)

"What is actually confirmed" lives in Git, not in gitignored `reports/` or
conversation memory. `labs/VALIDATED.md` is the committed record; the
contract test enforces its coverage.

## Matrix rules

- **Every registered check** (all four registries: wordpress, joomla,
  generic, php) has a row. Active-probe tables carry `Fixture | Probe |
  Disposition | Patched control | Lab | Validated | Commit`.
- `Validated` = date of the last live lab run; `Commit` = short hash that
  shipped the validation. Non-CONFIRMED rows use `—`.
- CONFIRMED rows must point at an existing `labs/` dir (contract-enforced).
- Passive-only tables (`| CVE | Note |`) record the **blocker**: missing
  package, vague advisory, needed credentials, or no safe harness.
  WPVDB entries have no CVE — track them under their WPScan IDs; the
  `PROOFCMS-K2-REGISTRATION-AVATAR` companion probe is tracked by module ID.
- Record negative results, not just confirmations: parked Slider Revolution,
  unsourcable Keydatas branch, the 1.57.3 input-sanitizer behavior, patched
  controls that returned `NOT_CONFIRMED`.

## Requirement tracking

`labs/REQUIREMENTS.md` is the acquisition matrix: one representative
vulnerable release per CVE/branch, archive location, and — for every
passive-only module — why no fixture is needed or what blocks one
(version-detection-only notes, Windows-VM requirements, commercial
archives, config-dependent NGINX/.NET advisories).

## Dispositions

`CONFIRMED` (live PoC ran) · `NOT_CONFIRMED` (ran, did not confirm) ·
`BLOCKED_EXTERNAL` (could not run — record why) · `NOT_YET_VALIDATED`
(unit-tested probe, no live run yet) · `AGGRESSIVE_SENT` (blind, unconfirmed).
