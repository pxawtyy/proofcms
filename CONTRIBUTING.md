# Contributing

## Target data is ephemeral

Never commit target-identifying data to this public repository:

- hostnames, subdomains, or IP addresses of scanned systems
- government/education domains
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

## Fast WordPress lab

For plugin CVEs, reuse the pinned stack instead of building a new compose:

```bash
python tools/wp_lab.py up
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/woocommerce.8.6.1.zip
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/woocommerce-payments.5.6.1.zip
python -m proofcms -u http://127.0.0.1:9212 --cve CVE-2023-28121 --run-exploit CVE-2023-28121 --exploit-mode safe --i-understand-authorized --i-understand-lab-only
python tools/wp_lab.py reset
python tools/wp_lab.py down
```

`install` accepts a URL or a local zip; `reset` drops the database and
reinstalls WordPress in place, so the base container is never rebuilt.
