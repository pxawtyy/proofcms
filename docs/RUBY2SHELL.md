# Ruby2Shell inventory check (CVE-2026-132825)

`tools/ruby2shell_check.py` classifies a local Ruby runtime against the
Ruby2Shell fix. It is an inventory helper: it parses `ruby -v` and never sends
the malformed case-conversion input or attempts the heap-grooming/RCE chain.

## Usage

```bash
# Local runtime
python tools/ruby2shell_check.py

# JSON for automation
python tools/ruby2shell_check.py --json

# Explicit version (useful on Windows or for a remote inventory)
python tools/ruby2shell_check.py \
  --version-string "ruby 3.4.12 (2026-10-23 revision 366f5fdc00) [x86_64-linux]"

# Also verify the ISO-8859-1 case-map path (safe one-byte input)
python tools/ruby2shell_check.py --probe
```

The optional `--probe` runs:

```ruby
s = ("\xDF").force_encoding("ISO-8859-1"); print s.upcase
```

It expects `SS` and only proves that the legacy-encoding path is available; it
does not trigger the overflow.

## Verdicts

| Verdict | Meaning |
|---|---|
| `AFFECTED` | Ruby 3.3.0-3.3.13, 3.4.0-3.4.12 or 4.0.0-4.0.9. |
| `EOL_AFFECTED` | Ruby 3.2 or older; vulnerable with no upstream fix. |
| `PATCHED` | Ruby 3.3.14+, 3.4.13+, 4.0.10+, or a later branch. |
| `UNKNOWN` | Ruby not found or the version could not be parsed. |

## Version matrix

| Branch | Affected | Fixed |
|---|---|---|
| Ruby 4.0 | 4.0.0 - 4.0.9 | 4.0.10 |
| Ruby 3.4 | 3.4.0 - 3.4.12 | 3.4.13 |
| Ruby 3.3 | 3.3.0 - 3.3.13 | 3.3.14 |
| Ruby 3.2 and older | all releases back to 2.4.0 | EOL |

UTF-8 strings take a different case-mapping path and are not affected. The
vulnerable path is selected by ISO-8859-x / Windows-125x encodings.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | `PATCHED` |
| `1` | `AFFECTED` or `EOL_AFFECTED` |
| `2` | `UNKNOWN` |

## Lab

`labs/cve-2026-132825` reproduces the one-byte out-of-bounds write with
Valgrind on Ruby 3.4.12; Ruby 3.4.13 is the control. The lab proves the memory
primitive only. The public RCE chain is not available yet.

```bash
docker compose -f labs/cve-2026-132825/compose.yml build
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-vuln
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-control
```

## Notes

- GHSA-34m4-m9fh-gqp5 is rated **Critical** and says PoCs can trigger RCE in
  some scenarios. NVD scores the CVE 7.4 (`AV:L/AC:H`). Veria Labs claims RCE
  on stock Rails; its public PoC is scheduled for 2026-11-25. Treat the
  inventory verdict as a runtime exposure signal, not as an RCE proof.
- Self-hosted products that bundle Ruby need the vendor's fixed release
  (GitLab, Mastodon, OpenProject, Chatwoot, Discourse base image, GitHub
  Enterprise Server).
- The standalone research reproduction is
  <https://github.com/evenomn/CVE-2026-132825>.
