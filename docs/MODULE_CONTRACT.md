# Module contract

## Evidence before likelihood

`LIKELY_VULNERABLE` means the version is in range **and** the vulnerable
component or surface was observed:

- ASP.NET: `ScriptResource.axd`/`WebResource.axd`, `__VIEWSTATE`, `ScriptManager`
- Forms Authentication: `.ASPXAUTH` or a FormsAuthentication login form
- plugins: the vulnerable endpoint or asset is reachable
- network services: the affected listener/protocol is present

If the version is in range but the surface is absent, return `INCONCLUSIVE`
(or `NOT_AFFECTED` when the feature is definitively unused). Never promote to
`CONFIRMED` from a version string, and set `exploit_ran=True` only after the
request was actually sent.

Passive advisory modules with no active probe may report a version match, but
the detail must say "version match only" and `exploit_available` must be
`False`. Modules with an aggressive probe may report the version match in
passive mode; the aggressive run is what proves the issue.

## HTTP client

Always pass `base_url=` (or use absolute URLs) when a module requests relative
paths. `HttpClient` without a base returns `status=0` plus an `error`; do not
treat that transport failure as "surface absent". `tests/test_http_contract.py`
enforces this for the package.

## Evidence path

Detector `source` must include the response path that produced the version,
for example `/login.aspx:X-AspNet-Version`, not just `/:X-AspNet-Version`.
This lets a report distinguish the app that emitted the header from the
landing page.

## Target data

Follow [`CONTRIBUTING.md`](../CONTRIBUTING.md): placeholders only, evidence in
gitignored `reports/`/`logs/`, and `python -m proofcms.redaction --all` must
pass before a push.
