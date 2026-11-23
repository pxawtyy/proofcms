# Real-world run: URL loop and ASP.NET fingerprinting (2026-11-23)

An authorized, unauthenticated scan of a public ASP.NET portal surfaced one
URL-handling defect and three false-positive classes. Target-specific evidence
stays in the gitignored `reports/` tree; this note records the generic cause and
the shipped fixes.

## F9 — document target became a directory and closed a redirect loop

Passing a document URL such as `https://target.example/app.aspx` made the
client request `https://target.example/app.aspx/`. The server answered with a
relative redirect:

```text
301 Location: applogin.aspx
```

Resolved from the synthetic directory, that became
`/app.aspx/applogin.aspx`, which returned the same relative `Location` again.
The loop ended only when the HTTP client hit its redirect limit
(`TooManyRedirects`). Pointing the scan at `applogin.aspx` avoided the loop, but
the underlying URL handling was wrong.

Cause and fix:

- `probe_target_baseline` appended `/` and the canary path directly to the
  target, even when the target named a document.
- `HttpClient._resolve_url` treated every base URL as a directory.
- `application_base_url()` now strips a document segment before the scan root
  is used, and the CLI scans from that directory while keeping the original
  target in the report.
- `TooManyRedirects` is now reported as a concise transport error with the last
  hop instead of the raw client exception.

Regression coverage: `tests/test_http_contract.py` checks document bases,
baseline URL construction, and the absence of `app.aspx/` requests.

## False positive — classic ASP.NET treated as ASP.NET Core

The ASP.NET detector set `detected=True` for any `ASP.NET_SessionId` cookie.
Core-only modules (Kestrel, Blazor, SignalR, DataProtection) then reported
`DETECTED_VERSION_UNKNOWN` even though the target was classic ASP.NET/IIS with
no Kestrel listener.

Fix:

- The detector now records a separate `core_detected`/`core_source` from strong
  Core evidence only: `Server: Kestrel`, an `.AspNetCore.*` cookie,
  `X-Powered-By: ASP.NET Core`, or a Blazor asset.
- Core-only modules gate on `core_detected`. A classic fingerprint returns
  `NOT_AFFECTED` with the classic evidence in the detail.
- `ASP.NET_SessionId` remains useful for classic ASP.NET checks, but never for
  Core-only advisories.

## False positive — .NET Framework 4.x reported as "version unknown"

The legacy .NET Framework advisories treated every non-2.0/3.x version as
`DETECTED_VERSION_UNKNOWN`. When the target disclosed
`X-AspNet-Version: 4.0.30319`, the tool ignored the branch information.

Fix: `runtime_finding` now reports `INCONCLUSIVE` with an explicit 4.x branch
and the reason (the servicing build and patch level are not observable over
HTTP). `DETECTED_VERSION_UNKNOWN` is reserved for fingerprints that expose no
branch at all.

## False positive — padding oracle and FormsAuth without their surface

`CVE-2010-3332` and `CVE-2011-3416` stopped at the version verdict and returned
`INCONCLUSIVE` even when the probe found no `.axd`, no `__VIEWSTATE`, and no
`.ASPXAUTH`. The feature was definitively unused.

Fix: both modules probe the surface for every detected ASP.NET runtime. If at
least one path answered and none exposed the feature, the result is
`NOT_AFFECTED` (the tool's status for "not applicable"). If every probe failed
at the transport layer, the result stays `INCONCLUSIVE`, so a timeout is never
mistaken for absence.

## Status vocabulary

The contract uses `NOT_AFFECTED`; the real-world report called the same
outcome "NOT_APPLICABLE". Reports should map `NOT_APPLICABLE` to
`NOT_AFFECTED` rather than inventing a new status.
