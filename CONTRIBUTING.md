# Contributing

## Target data is ephemeral

Never commit target-identifying data to this public repository:

- hostnames, subdomains, or IP addresses of scanned systems
- government/education domains (for example, a `*.gov.br` or `*.edu.br` host)
- target codenames or report-directory names derived from a target
- vendor build IDs or exact stack versions tied to one deployment

Use placeholders instead:

| Do not commit | Use |
|---|---|
| a real target hostname | `target.example` |
| a real path | `/portal/`, `/app/`, `/login.aspx` |
| a real report directory | `target-report` |
| a target build ID | `10.1.8-<build>` |

Keep raw evidence in `reports/` or `logs/` (both gitignored) and redact it
before sharing. The checker prints only file, line, and rule — never the
matched value — so CI logs cannot re-expose it.

## Local guard

Enable the pre-commit hook once per clone:

```bash
git config core.hooksPath .githooks
```

The hook runs `python -m proofcms.redaction --staged`. CI runs the same
check over every tracked file with `python -m proofcms.redaction --all`.

## Tests

```bash
python -m pytest -q
ruff check proofcms tests
mypy proofcms
python -m proofcms.redaction --all
```
