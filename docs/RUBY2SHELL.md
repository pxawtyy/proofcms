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
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-vuln sh /lab/run_crash.sh
docker compose -f labs/cve-2026-132825/compose.yml run --rm ruby-control sh /lab/run_crash.sh
```

The vulnerable runs report the Valgrind invalid write and read; the control
reports neither. The native N=1244 diagnostic aborts in the allocator on
3.4.12 (exit 134/139) and survives on 3.4.13.

## Review summary (2026-11-21)

- Demonstrated: a one-byte out-of-bounds write (`S`/`s`), a one-byte
  out-of-bounds read, a native availability abort on glibc 2.41 (N=1244
  victim/guard diagnostic), and a web-facing availability abort via a Rack
  multipart `_method` request, a loopback Puma server, and a multi-worker
  Puma run (3/3 failed requests, workers restarted).
- Impact on the lab runtime (glibc 2.41): memory-safety violation, native
  availability, and web-facing availability via Rack/Puma; no integrity or
  confidentiality impact is demonstrated.
- The pointer-verified jemalloc tracer shows the guard is not adjacent
  (`guard0=0x43`, `input0=0xdf` on both builds); the `next=0x53` is the output
  string's first byte, not a changed guard. No adjacent data modification is
  demonstrated; the negative does not rule out the class because adjacency was
  not established.
- Rack multipart path (verified): Rack 3.2.9's multipart parser tags a part
  body with the part's `charset` (`tag_multipart_encoding` ->
  `body.force_encoding`) and `Rack::MethodOverride` calls `upcase` on
  `_method`. A part with `charset=ISO-8859-1` reaches `case_map`; the N=1244
  request aborts 3.4.12, and a live Puma worker dies (exit 134; multi-worker
  3/3 failed requests) while 3.4.13 returns 200. Query/form-urlencoded data
  defaults to UTF-8/ASCII-8BIT; the multipart part charset is the reachable
  gap.
- NVD CVSS 3.1 7.4 (`AV:L/AC:H`). The independent review's second pass
  classified the Rack/Puma path as web-facing availability (AV:N/AC:L, High for Rack
  deployments) and noted that the AV:L vector is not defensible for web-facing
  triage. Integrity and confidentiality remain not demonstrated.
- Remaining evidence for a higher impact: a jemalloc setup with a truly
  adjacent canary (the current tracer shows the guard is not adjacent; an
  adjacent-canary attempt found A/B but the mapping did not reuse A, so
  `B[0]` stayed `0x43` and the test is inconclusive); the exit-139 backtrace is
  optional (the latest abort is 134). No further glibc adjacent-chunk research
  is warranted; the allocator aborts.

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
