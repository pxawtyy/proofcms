# Lab authoring and validation

Start from `labs/_template/` (`compose.yml` checklist + `README.md` with the
port table and README skeleton). Every lab: `compose.yml`, seed script(s),
`README.md` (bring-up, proof command, expected results both ways, cleanup,
teardown).

## Rules

- Loopback only: `127.0.0.1:<port>:80`. Pick a free port from the table in
  `labs/_template/README.md` and add your row.
- Networks: use `lab: {}` (plain). **Do not** mark the lab network
  `internal: true` — the host must reach the published port, and stale
  attachments break DNS; after changing networks, `down` (not just `up`)
  before recreating.
- Pin every image with its **amd64 platform digest** (containerd snapshotter
  cannot resolve manifest-list digests):
  `docker buildx imagetools inspect <image> --format "{{json .Manifest}}"`
  and take the `amd64/linux` entry. `wordpress:cli` → `wordpress:cli-php8.1`.
- Seed scripts live in the lab dir (`seed.ps1`, `seed-admin.php`,
  `make-zip.php`). Idempotent where cheap. Commercial packages are mounted
  read-only from `D:/ProofCMS-Labs/archives` and zipped **inside** the
  container — no package bytes in Git.
- Validate end-to-end, then `docker compose down -v`. Vulnerable run must
  yield the expected `VULNERABLE`/`CONFIRMED`; patched control (where a fixed
  release exists) must yield `NOT_CONFIRMED`/`PATCHED`. Delete proof
  artifacts the probe cannot (uploaded files, canary dirs) and document it.
- Update `labs/VALIDATED.md` (Lab + Validated + Commit columns) in the same
  commit; some CONFIRMED rows share one lab (8869+8870).

## Joomla 3.x bootstrap (no CLI installer)

1. Wait for `installation/sql/mysql/joomla.sql` inside the web container.
2. `docker cp` it out, replace `#__` with your prefix, import via MariaDB.
3. Copy hand-written `configuration.php`, `rm -rf installation`.
4. Admin user: hash **inside the container** (`seed-admin.php` with
   `password_hash()` + prepared statement). Host-shell round-trips corrupt
   bcrypt hashes (PHP warnings pollute stdout — the 15882 lesson).

## Known Joomla behaviors (do not re-derive)

- CVE-2026-90915 canary dir **must start with `cache`** (prefix check in
  `FileStorage::_deleteFolder`); traversal group `../../cache-proofcms`.
- CVE-2016-8869: group 7 (Administrator) works and logs into
  `/administrator/`; group 8 is rejected by `JUser::save()` — do not claim
  Super User. Seed with `allowUserRegistration=0` + `useractivation=0` for
  the 8870 precondition.
- CVE-2018-15882: only the short-tag PHAR stub (`<? __HALT_COMPILER(); ?>`)
  in `.gif` bypasses 3.8.11 `InputFilter`; needs an admin session
  (`--aggressive-arg admin_user/admin_password`); delete
  `/var/www/html/images/proofcms-*.gif` after each run.
- SP Page Builder install: the package postflight calls
  `UpdatesitesModel::rebuild()`, which always fails under CLI (needs an
  interactive admin) — non-fatal. Verify with `extension:list`, not the
  exit code.
- RSFiles install: scripted admin-UI "Install from Folder" (no Joomla 3 CLI
  installer). Warm-up GET to `com_rsfiles` first; no creds needed for the
  probe; delete `/var/www/html/downloads/jvh-rsfiles-*.php` after runs.
- 90915 probe needs no upload surface; 57827 probe needs no creds.
