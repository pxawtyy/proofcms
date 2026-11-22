# Gotchas (already paid for — do not repay)

## PowerShell / shell

- The `shell` tool runs `pwsh`. Quote paths with spaces/special chars;
  `docker cp` with Windows paths needs quotes. Prefer dedicated file tools
  over shell for reads/edits.
- Avoid heredocs, `<<`, `<` redirection, and `for` loops in `shell` — the
  portable scanner rejects them. One-liners or temp scripts instead.
- `curl.exe -s -o NUL -w "%{http_code}\n"` for checks; `curl` alone may hit
  proxy env vars (`no_proxy` covers 127.0.0.1).
- Pipes to `head`/`tail` on `git diff` output can fail with pipe-closed
  errors; keep piped output small.

## Python / venv

- System `python` (3.12.10, has pytest/ruff/mypy) is the check runner. The repo
  `.venv` is broken for exes (`python.exe`, `proofcms.exe` fail with uv
  trampoline errors) — but `.venv\Scripts\python.exe` historically ran
  probes; prefer system `python` unless a probe needs venv deps.
- Tests run from the repo root so `proofcms.*` imports resolve.

## Docker on this workstation

- Docker Desktop data lives on `D:` (`D:\DockerDesktopData\...` junction);
  archives live in `D:/ProofCMS-Labs/archives` — never in the repo.
- After editing compose networks, `down` before `up` (stale attachments
  break DNS: `getaddrinfo for db failed`).
- `docker exec ... sh -c '...'` with nested quotes: prefer writing a small
  SQL/PHP file and `docker cp` + exec the file over inline quoting.
  MariaDB note: `mariadb -uroot -proot joomla -N < /tmp/q.sql` (file input
  avoids shell-quoting hell).

## Joomla specifics

- bcrypt via host shell is lossy — always hash inside the container.
- `configuration.php` values that matter: `$host='db'`, `$dbprefix`,
  `live_site` matching the loopback URL, `session_handler='database'`.
- Re-running a seed after `installation/` was removed: guard on
  `configuration.php` presence instead of waiting for installer files.
- Joomla asset-rule JSON is `action -> group id -> allow`, e.g.
  `{"core.admin":{"7":1}}`. Writing it group-first (`{"7":{"core.admin":1}}`)
  parses as a bogus action named `7` and grants nothing — the user then fails
  `allowSave()`/`canView()` with an unrelated 403. Verify the ACL inside the
  container (`$user->authorise('core.admin','com_users')`) before trusting a
  permission fixture.
- Component-level `core.admin` works: grant it on the component asset to make a
  delegated component admin who is not a global Super User. `root.1` alone
  does not grant it.
- When building a source bundle from two upstream releases, do not pick files
  from the diff `--stat` alone. Check that the changed files actually match the
  advisory's subject: a triage packet for an HTTP/3 overflow shipped core/startup
  hunks because those were the files in the selected version pair, and the
  reviewer correctly flagged the mechanism as absent. Verify the changed file
  names against the advisory description before packetizing.

## Evidence / tests

- `NOT_CONFIRMED` contains the substring `CONFIRMED` — match dispositions
  with `(?<![A-Z_])CONFIRMED`, never plain `in`.
- Thread-local transcript ring is shared: drain it at the start of
  order-dependent tests.
- Renaming a module-level helper breaks `patch(...)` targets in tests —
  grep tests for the old name first; keep thin compat wrappers.
- `Finding.evidence` flows to JSON + text reports; `redact_output` handles
  nested dicts/lists; transcript entries must stay small (no bodies).
