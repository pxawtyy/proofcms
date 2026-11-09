# Agent instructions — ProofCMS

ProofCMS is a modular Python toolkit that detects Joomla/WordPress and
validates known CVEs with explicit evidence. Read this file first, then the
focused file for your task.

## Repo layout

- `proofcms/modules/<cms>/` — one file per CVE check (`check()` + `metadata()`).
  Shared logic belongs in `proofcms/core/`, never copy-pasted per module.
- `proofcms/core/` — `http.py` (transport), `probes.py` (CSRF/tokens),
  `auth.py` (logins), `crawl.py` (page discovery), `args.py`
  (aggressive args), `transcript.py` (proof transcripts), `cleanup.py`
  (lab-cleanup convention), `differential.py` (non-mutating differentials),
  `evidence.py` (PHP-math payloads, SQL errors).
- `labs/` — reproducible loopback-only Docker labs (see `labs.md`).
- `labs/VALIDATED.md` — the committed record of what is confirmed (see
  `validation.md`). `reports/` stays gitignored; conclusions live here.
- `tests/test_module_contract.py` — enforces module ↔ tests ↔ matrix rows.

## Non-negotiables

1. **Loopback only.** Publish ports as `127.0.0.1:<port>:80`. Never `0.0.0.0`.
   Tear down with `docker compose down -v` when done.
2. **CONFIRMED means a live run.** Never promote `LIKELY_VULNERABLE` from
   version matching alone. A new lab counts only after it validates
   end-to-end (vulnerable + patched control where a fixed release exists).
3. **Never commit** package archives, DB dumps, fixtures, or credentials.
   Mount read-only from `D:/ProofCMS-Labs/archives`.
4. **Pin amd64 platform digests**, not manifest-list digests (see `labs.md`).
   `wordpress:cli` has no stable digest — use `wordpress:cli-php8.1` pinned.
5. **Same-commit rule:** new module ⇒ unit tests + `labs/VALIDATED.md` row
   (+ lab dir for CONFIRMED) in the same commit. The contract test enforces it.
6. **LF line endings** (`.gitattributes`); do not commit CRLF conversions.

## File index

- `workflow.md` — dev loop: test/lint/typecheck commands, commit format, push.
- `labs.md` — authoring and validating Docker labs, seed patterns, ports.
- `validation.md` — validation-matrix rules, dispositions, blocker rows.
- `framework.md` — the five shared core pieces with usage snippets.
- `gotchas.md` — Windows/PowerShell/Docker/Joomla pitfalls that already bit us.
