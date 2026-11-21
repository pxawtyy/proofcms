# Ruby2Shell inventory check (CVE-2026-132825)

`tools/ruby2shell_check.py` classifies a local Ruby runtime against the fix. It
is an inventory helper: it parses `ruby -v` and never sends the malformed
case-conversion input or attempts a heap chain.

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
vulnerable path is selected by exactly 14 single-byte encodings: ISO-8859-1,
-2, -3, -4, -9, -10, -13, -14, -15, -16 and Windows-1250, -1252, -1254, -1257.
Other single-byte encodings in those families are not affected. `capitalize`
is not a trigger: the titlecase flag clears the upcase flag after the first
character, so only the first sharp-s expands.

## Lab

`labs/cve-2026-132825` reproduces the one-byte out-of-bounds write and the
matching one-byte out-of-bounds read with Valgrind on Ruby 3.4.12; Ruby 3.4.13
is the control. The naive 21-byte input and the mixed N=28 geometry are
included.

```bash
docker compose -f labs/cve-2026-132825/compose.yml build
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-vuln
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-control
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-vuln sh /lab/run_mixed.sh
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-control sh /lab/run_mixed.sh
```

The vulnerable runs report the Valgrind invalid write and read; the control
reports neither. A native run of the mixed input completes without a crash on
the lab image (glibc 2.41).

## Review summary (2026-11-21)

- Demonstrated: a one-byte out-of-bounds write (`S`/`s`) and a one-byte
  out-of-bounds read in the affected single-byte case-conversion path.
- Impact on the lab runtime (glibc 2.41): only the Valgrind-detected write and
  read; no native crash was observed for the mixed input, and no integrity or
  confidentiality impact is demonstrated.
- Non-headered allocators such as jemalloc could expose adjacent live payload
  instead of chunk metadata; that is structurally plausible but not
  demonstrated.
- Default Rails/Rack/Sinatra decode request data as UTF-8 or ASCII-8BIT, so
  reaching the affected path requires an application that preserves one of the
  14 encodings. Veria Labs' default-deployment claim is unverified.
- NVD CVSS 3.1 7.4 (`AV:L/AC:H`). The advisory is rated Critical; treat the
  inventory verdict as an exposure signal, not as a higher-impact proof.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | `PATCHED` |
| `1` | `AFFECTED` or `EOL_AFFECTED` |
| `2` | `UNKNOWN` |

## Notes

- Self-hosted products that bundle Ruby need the vendor's fixed release
  (GitLab, Mastodon, OpenProject, Chatwoot, Discourse base image, GitHub
  Enterprise Server).
- The standalone research reproduction is
  <https://github.com/evenomn/CVE-2026-132825>.
