# Dev workflow

## Toolchain (Windows)

Use the **system** `python` for checks — the repo `.venv` has broken
`uv`-trampoline exes (`pytest`, `ruff` binaries fail there):

```powershell
python -m pytest -q -p no:cacheprovider   # full suite (~50 s, 423 tests)
python -m pytest tests/test_x.py -q -p no:cacheprovider
python -m ruff check .
python -m mypy proofcms                   # 125 files, must be clean
```

Only `ruff check` (not format) is enforced; `mypy` runs on `proofcms/`.
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
