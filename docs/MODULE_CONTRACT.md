# Module contract

## Evidence before likelihood

`LIKELY_VULNERABLE` means the version is in range **and** the vulnerable
component or surface was observed:

- ASP.NET: `ScriptResource.axd`/`WebResource.axd`, `__VIEWSTATE`, `ScriptManager`
- ASP.NET Core: `Server: Kestrel`, an `.AspNetCore.*` cookie, or a Blazor asset.
  `ASP.NET_SessionId` and `X-AspNet-Version` are classic ASP.NET/IIS markers and
  must not make a Core-only advisory applicable.
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

## Designing proofs: prefer non-mutating differentials

Reflection alone never proves evaluation. A marker echoed back verbatim may
simply have been reflected, so new probes must demonstrate that the server
*acted* on the input — without writing files or changing state when a
differential allows it:

- **Known-output differential.** Submit a registered construct whose handler
  renders fixed, observable output (e.g. a self-evaluating shortcode with no
  attributes) and require both the marker and the handler output in the
  response. `proofcms.core.differential.confirm_shortcode_output` implements
  this; CVE-2026-92229 is the reference user.
- **Validation-error differential.** Submit input that only a trusted code
  path validates, and key the verdict on a field-specific validation error
  (CVE-2026-15748: the forged upload field is rejected while an identical
  baseline is processed normally). Nothing is written.
- **Do not claim evaluation from reflection.** A public Forminator PoC treated
  a reflected marker as exploitation even though `esc_url()` had already
  percent-encoded the brackets, so no shortcode could parse. Require handler
  output or a behavioral difference instead.

## Shared framework (do not re-implement per module)

Five patterns used to be copy-pasted across modules; they live in core now:

- **Authenticated sessions** (`proofcms/core/auth.py`): `joomla_admin_login` /
  `verify_joomla_admin_login` and `wordpress_admin_login`. Module-level
  `admin_login` / `verify_admin_login` wrappers stay as thin delegates so
  existing tests keep patching the same names.
- **Page discovery** (`proofcms/core/crawl.py`): `crawl_pages` (seed paths +
  same-site homepage `href` crawl) and `rest_list_links` (`?rest_route=`
  listings). HTML field parsers stay in their modules.
- **Named aggressive arguments** (`proofcms/core/args.py`): repeatable
  `--aggressive-arg KEY=VALUE`, parsed once in the CLI and handed to every
  `check()` as the `aggressive_args` mapping. New probes read named keys;
  legacy `--aggressive-command` strings keep working as a fallback.
  Document the keys in the `--aggressive-arg` help and the lab README.
- **Proof transcripts** (`proofcms/core/transcript.py`): `HttpClient`
  records a lightweight entry (method, scrubbed URLs, status, body hash, and
  `waf` when a challenge page is detected) per exchange, and the stateless
  `request()` helper keeps a thread-local ring. The CLI wraps every
  `module.check()` with `begin_capture()` / `end_capture()` and automatically
  attaches the transcript to `VULNERABLE` / `VULNERABLE_UPLOAD_ONLY` findings
  when the module did not attach one. It also promotes `exploit_ran=True` when
  an active check made at least one HTTP request. Modules may still attach a
  richer session transcript explicitly with `attach_transcript(evidence, sess)`
  or `take_transcript()`. Bodies are never stored.
- **Lab cleanup** (`proofcms/core/cleanup.py` + `proofcms --lab-cleanup CVE`):
  modules that create artifacts expose `cleanup(target_url, *, timeout,
  proxy, aggressive_args, aggressive_command)` returning `cleanup_result()`
  (`removed` / `remaining` / `manual`). For statically served uploads, use
  `cleanup_http_artifact(...)`, which reads `file`/`path`/`url` from
  `--aggressive-arg`, verifies each artifact over HTTP, and reports what the
  application cannot unlink. The module contract requires a valid `cleanup()`
  hook for any module that sets `uploaded_filename` or performs an aggressive
  file write. Prefer exact IDs from the probe report (`file_hash`,
  `folder`/`file`/`token`), fall back to sweeping the module's known
  `proofcms-*` patterns, and always report dotfiles and folders HTTP cannot
  delete as `manual` shell steps. `proofcms --lab-cleanup` lists modules with
  hooks when the CVE has none.

## CMS version scope

The CLI passes the detected core CMS version as the second positional argument
only when `metadata()["cms"] == info.name`. A Joomla core module on a detected
Joomla target receives `info.version`; plugin, extension, and runtime modules
receive `None` and must use their own detector/runtime data (`plugins`,
`php_runtime`, `aspnet_runtime`, `nginx_runtime`, `node_runtime`). Never use
`cms_version` as a fallback for a plugin or runtime version: doing so produced
cross-version false positives (for example, treating WordPress 6.7 as an
ASP.NET Core version).
