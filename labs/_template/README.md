# Lab authoring template

Copy this directory to `labs/cve-<id>/` (lowercase CVE, e.g.
`labs/cve-2026-90915/`) and work through the checklist in `compose.yml`.
Every CONFIRMED PoC in ProofCMS must ship with a lab directory; the module
contract test (`tests/test_module_contract.py`) enforces a `labs/VALIDATED.md`
row, and CONFIRMED rows must point at a lab that exists.

## Automation levels

Prefer fully automated labs:

1. **Automated** — `docker compose up -d --wait`, one setup command
   (`wp core install`, Joomla CLI `installation/joomla.php install`, SQL
   import, `wp eval-file`), then the PoC runs green with no human input.
2. **Guided** — automation covers everything scriptable; the README lists the
   exact remaining manual commands (e.g. a web-installer step that has no CLI
   equivalent) with expected outputs. Say which steps are manual and why.

Do not ship a lab you have not run end-to-end (vulnerable *and* patched
control where a fixed release exists). Record both runs in the README.

## Rules

- Loopback only: publish ports as `127.0.0.1:<port>:80`. Never `0.0.0.0`.
- Allocate a free port from the table below and add your row when you do.
- Pin every image with its amd64 platform digest (`image:tag@sha256:...`).
  Containerd needs platform digests, not manifest-list digests. Get it from
  the exact image you validated with:
  `docker buildx imagetools inspect <image> --format "{{json .Manifest}}"`.
  `wordpress:cli` has no stable digest — use `wordpress:cli-php8.1` pinned.
- Never commit fixtures, database dumps, archives, or credentials.
  Mount archives read-only from `D:/ProofCMS-Labs/archives` via env vars
  (see `labs/cve-2026-32475` and `labs/cve-2026-21627`), and document the
  required package and version in `labs/REQUIREMENTS.md`.
- Seed scripts live in the lab dir (`setup-*.php`, `*.sql`). Keep them
  idempotent where cheap (skip if the seeded object already exists).
- Tear down with `docker compose down -v` when done; the lab must be
  rebuildable from scratch.
- Clean up lab-created artifacts the PoC cannot delete itself (uploaded
  files, entries, canary directories) — document the exact cleanup.

## Port allocation (loopback `127.0.0.1`, keep sorted)

| Port | Lab | Target |
|---|---|---|
| 8091 | `labs/cve-2026-87902` | WordPress 7.0.2 |
| 8092 | `labs/cve-2026-60137` | WordPress 6.9.x / 7.0.x |
| 8093 | `labs/cve-2026-32475` | WordPress 6.3.1 + Elementor |
| 8095 | `labs/cve-2026-92229` | WordPress 6.5 + Forminator 1.57.2 |
| 8096 | `labs/cve-2026-15748` | WordPress 6.5 + Forminator 1.56.1 |
| 8097 | `labs/cve-2026-90915` | Joomla 5.4.8/5.4.9 |
| 8098 | `labs/cve-2017-8917` | Joomla 3.7.0 |
| 8099 | `labs/cve-2016-8869` (also covers CVE-2016-8870) | Joomla 3.6.3 |
| 8100 | `labs/cve-2018-15882` | Joomla 3.8.11 (+3.8.12 control) |
| 8101 | `labs/cve-2026-48908` | Joomla 5.4.9 + SP Page Builder 6.0.0 |
| 8102 | `labs/cve-2026-57827` | Joomla 3.9 + RSFiles 1.16.29 |
| 8103 | (temporary) RSFiles 1.17.12 control | Same Joomla 3.9 stack; torn down after run |
| 9101 | `labs/cve-2026-109619` | PHP 8.2.34 upload-progress / session lab (reserved) |
| 9102 | `labs/cve-2026-109618` | PHP 8.3.35/8.3.36 OOM lab |
| 9103 | `labs/cve-2026-109619-cli` | PHP 8.3.35/8.3.36 cli-server leak lab |
| 9104 | `labs/cve-2015-8562` | Joomla 3.4.4 on PHP 5.6 lab |
| 9105 | `labs/cve-2012-1823` | PHP 5.3.12 CGI lab |
| 9106 | `labs/cve-2019-19576` (also covers CVE-2019-19634) | Joomla 3.6.3 + K2 2.8.0 lab |
| 9110 | `labs/cve-2019-11043` | PHP-FPM lab |
| 9157-9158 | `labs/cve-2021-23394` | elFinder lab |
| 9169-9170 | `labs/cve-2026-81891` | elFinder differential lab |
| 9206 | `labs/cve-2018-9206` | Blueimp lab |
| 9210 | `labs/wordpress-plugin-fixtures` | Shared WordPress fixture lab |
| 9216 | `labs/cve-2026-21627` | Joomla 5 lab |
| 9217 | `labs/cve-2024-40744` | Joomla 5.2.3 + Convert Forms 4.4.5 lab |
| 9219 | `labs/cve-2026-48907` | Joomla 5.2.3 + JCE 2.9.99.1 lab |
| 9221 | `labs/cve-2026-48939` | Joomla 6.1.0-rc1 + iCagenda 4.0.7 lab |
| 9223 | `labs/cve-2026-49049` | Joomla 3.10 + Helix3 2.2 lab |
| 9225 | `labs/cve-2026-57830` (also covers CVE-2026-57829) | Joomla 3.10 + Helix Ultimate 1.1.4 lab |
| 9220 | `labs/cve-2010-4166` | Joomla 1.5.21 (PHP 5.6 + MySQL 5.5) weblinks lab |
| 9220 | `labs/cve-2026-56291` | Joomla 5.2.3 + Balbooa Forms 2.4.0 lab |
| 9220 | `labs/cve-2026-61424` | Joomla 5.2.3 + DJ-Classifieds 3.11.1 lab (:9220 reused across labs; run one at a time) |
| 9226 | `labs/cve-2026-73373` | Joomla 5.4.7 + Convert Forms 5.0.4 SHTML lab |

## Minimal README skeleton

```markdown
# CVE-XXXX-XXXXX lab

What it proves, in one paragraph. Link the module.

## Bring-up

docker compose -f labs/cve-XXXX-XXXXX/compose.yml up -d --wait
... install/seed commands, each copy-pasteable ...

## Run the proof

python -m proofcms -u http://127.0.0.1:PORT ... (exact command)

Expected result on <vuln version>: STATUS/CONFIDENCE + key evidence.
Patched control (<fixed version>): expected result.

## Cleanup

Exact commands for anything the probe cannot delete itself.

## Teardown

docker compose -f labs/cve-XXXX-XXXXX/compose.yml down -v
```
