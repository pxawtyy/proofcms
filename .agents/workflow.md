# Dev workflow

## Toolchain (Windows)

Use the **system** `python` for checks — the repo `.venv` has broken
`uv`-trampoline exes (`pytest`, `ruff` binaries fail there):

```powershell
python -m pytest -q -p no:cacheprovider   # full suite (~870 tests, ~150 s)
python -m pytest tests/test_x.py -q -p no:cacheprovider
python -m ruff check .
python -m mypy proofcms tools             # 125+ files, must be clean
```

For a change set, prefer the fail-fast wrapper (stops at the first red
step; targeted pytest for module changes, full suite for core changes):

```powershell
python tools/verify.py
python tools/verify.py --full
```

Only `ruff check` (not format) is enforced; `mypy` runs on `proofcms/` and
`tools/`.
Pre-commit runs `ruff check` + trailing-whitespace + end-of-file-fixer +
`check-added-large-files --maxkb=500` (this is what blocks fixtures).

## Contract test

`tests/test_module_contract.py` enforces:

1. Every module with non-empty `exploit_modes` has referencing unit tests.
2. Every such module has a `labs/VALIDATED.md` row with a disposition.
3. Every CONFIRMED row points at an existing `labs/` directory.
4. **Every registered CVE** (all four registries) has a matrix row —
   passive-only modules link to what blocks active proof.

Run it alone: `python -m unittest tests.test_module_contract -v`.

## Commits

Conventional prefixes: `feat(labs):`, `feat(detect):`, `feat(knowledge):`,
`feat(framework):`, `chore(devex):`, `fix(...)`, `docs(labs):`.
Push to `main` after suite + ruff + mypy are green.

## CLI essentials

```bash
python -m proofcms -u http://127.0.0.1:PORT --cms joomla --cve CVE-XXXX \
  --run-exploit CVE-XXXX --exploit-mode aggressive \
  --aggressive-arg KEY=VALUE \   # repeatable; see framework.md
  --i-understand-authorized --i-understand-lab-only
python -m proofcms --lab-cleanup CVE-XXXX -u http://127.0.0.1:PORT \
  --aggressive-arg file_hash=<h> --i-understand-authorized --i-understand-lab-only
python -m proofcms --list-cves
```

`--aggressive-command` is legacy; prefer `--aggressive-arg`. Secrets in
args are redacted from reports automatically.

## Lab runners

```powershell
# WordPress: vulnerable + patched control in one compact JSON
python tools/wp_lab.py run labs/cve-2024-10402 --pretty

# Joomla: lab.json declares compose, seed, databases and proofs
python tools/joomla_lab.py validate labs/cve-2026-75949 --pretty
python tools/joomla_lab.py reset labs/cve-2026-75949
```

`validate` exits `0` only for `CONFIRMED_WITH_CONTROL`; `2` means inspect
the JSON. Snapshots live in `labs/**/.snapshots/` (gitignored).
