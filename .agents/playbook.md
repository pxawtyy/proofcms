# Playbook — the fast path for a validation task

Read `AGENTS.md` first. This file is the state machine for "what do I do
next" so the same shell archaeology is not repeated for every CVE.

## Fast-path tree

```text
New request
├─ Known CVE, module already registered?
│  ├─ CONFIRMED in labs/VALIDATED.md → stop; quote the existing row.
│  ├─ BLOCKED_EXTERNAL → check the blocker still exists; only reopen with a
│  │  new acquisition route or runtime, never by re-running the same probe.
│  └─ NOT_YET_VALIDATED → go to step 3 with the recorded fixture.
├─ New CVE with a public advisory/PoC?
│  ├─ Package obtainable → step 2 (source) → step 3 (lab) → step 4 (control).
│  └─ Package not obtainable after 3 routes → BLOCKED_EXTERNAL + evidence.
├─ Runtime/config advisory (NGINX, PHP, .NET, Java)?
│  ├─ Reproducible on this host → minimal lab, one observable.
│  └─ Needs another OS/CPU/VM → BLOCKED_EXTERNAL; do not blind-flood.
├─ WordPress plugin → `tools/wp_lab.py` (persistent CLI + SQL snapshot).
├─ Joomla extension → `tools/joomla_lab.py` + `lab.json`.
└─ Version-only signal → passive module; no lab and no CONFIRMED.
```

## Six-step checklist (every active validation)

1. **Classify.** Active or passive? Which exact package/branch? Is the
   archive in `D:/ProofCMS-Labs/archives`? Which runtime is required?
   Write the answer in one sentence before touching Docker.
2. **Ground the claim.** Open the vulnerable source and the fix. Record
   `path:line` for the sink, the reachable route, the auth/CSRF
   precondition, and the patched check. No endpoint from memory.
3. **Reproduce.** Start the smallest loopback lab with pinned amd64
   digests. Seed only what the route needs. One request, one observable.
4. **Prove and control.** Vulnerable run must produce the recorded
   observable; the patched run must not. Capture compact JSON
   (`vulnerable`, `patched`, `php_errors_tail`). A `200`/`500` alone is not
   proof.
5. **Record.** Same commit: module + unit tests + `labs/VALIDATED.md` row
   (+ lab dir for CONFIRMED) and keep `labs/REQUIREMENTS.md`,
   `docs/CANDIDATES.md`, and `docs/CVE-INDEX.md` in parity. Use
   `BLOCKED_EXTERNAL`/`NOT_YET_VALIDATED` honestly.
6. **Verify and commit.** `python tools/verify.py` (ruff → targeted pytest
   → contract → mypy), then a conventional commit and push.

## Runner commands

```powershell
# WordPress: one command for vulnerable + patched control (compact JSON)
python tools/wp_lab.py run labs/cve-2024-10402 --pretty

# Manual WordPress loop
python tools/wp_lab.py up
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/forminator.1.35.1.zip
python tools/wp_lab.py reset
python tools/wp_lab.py down

# Joomla: lab.json carries compose, seed, databases, proofs
python tools/joomla_lab.py up labs/cve-2026-75949
python tools/joomla_lab.py seed labs/cve-2026-75949
python tools/joomla_lab.py snapshot labs/cve-2026-75949
python tools/joomla_lab.py validate labs/cve-2026-75949 --pretty
python tools/joomla_lab.py reset labs/cve-2026-75949
python tools/joomla_lab.py down labs/cve-2026-75949

# Change-set verification (stops at the first red step)
python tools/verify.py
python tools/verify.py --full
```

Exit codes from `validate`: `0` = vulnerable + patched control
(`CONFIRMED_WITH_CONTROL`), `2` = not fully confirmed. Treat `2` as
"inspect the JSON", never as success.

## Stop-loss (hard limits)

- **Two hours** on one fixture without a new observable → park as
  `BLOCKED_EXTERNAL`, record exactly what was tried.
- **Three** failed payload variants → stop guessing; return to the source
  and the patch diff. Blind fuzzing is not validation.
- **Three** acquisition routes (vendor, GitHub tags/releases, mirrors) with
  no archive → blocked; do not keep searching.
- **No blind floods.** No NGINX/PHP stress loops, no credential spraying,
  no wordlist runs. Use the source and a single differential.
- **Do not retry known blockers** (Exchange ViewState, Java4Shell AVX-512,
  Windows-only PHP-CGI, NGINX build/pcap, paid or unsourcable packages) without
  a new artifact. J3 miniOrange (77995) and the SPPB dynamic-content/addon
  routes (65766/67285) were once listed here and are now CONFIRMED in
  `labs/VALIDATED.md` — quote those rows instead of reopening them.
- **Never** promote a version match, a scanner banner, or a `200` to
  `CONFIRMED`. `CONFIRMED` requires a live PoC and a patched control where
  a fixed release exists.
- **One** full-suite run per change set. During iteration use
  `python tools/verify.py`; `--full` is for the final check.

## Grounding rules

- Every claim cites a concrete artifact: `path:line`, advisory URL, commit
  hash, HTTP request/response, or lab JSON. "Probably" is not evidence.
- Read the patched code before writing the control expectation. If the fix
  is a version gate with no behavioral difference, say so.
- Prefer one differential with a time/canary observable over many payloads.
- Keep DB dumps, plugin zips, and snapshots out of Git; they live in
  `labs/**/.snapshots/` or `D:/ProofCMS-Labs`.
- Record negative results and blocked reasons; they prevent the next agent
  from repeating the work.
- If the task is documentation-only, do not start Docker. If it is a status
  change, update all four registries in the same commit.

## Tool map

| Tool | Use |
|---|---|
| `tools/wp_lab.py` | Persistent WordPress + MariaDB fixture; plugin install, SQL/plugin snapshot, `validate` |
| `tools/joomla_lab.py` | Declarative Joomla stack/seed/snapshot/validate from `lab.json` |
| `tools/verify.py` | Fail-fast ruff → targeted pytest → contract → mypy |
| `tools/record_validation.py` | Append/replace a `labs/VALIDATED.md` row |
| `tools/archive_index.py` | Inventory local package archives |
| `tools/java4shell_check.py` | Host AVX-512 VBMI capability check |
| `tools/ruby2shell_check.py` | Local Ruby2Shell version/legacy-encoding check (CVE-2026-132825) |
