# Shared framework (do not re-implement per module)

## 1. Logins — `proofcms/core/auth.py`

```python
from ...core.auth import joomla_admin_login, verify_joomla_admin_login, wordpress_admin_login
ok = joomla_admin_login(sess, base, user, pwd, timeout=12)          # bool; strict_status=False = legacy media behavior
res = verify_joomla_admin_login(url, username=u, password=p)        # {"logged_in","status","final_url"[,"reason"]}
ok, final = wordpress_admin_login(sess, base, user, pwd)            # ("/wp-admin/" + "Dashboard")
```

Keep module-level `admin_login` / `verify_admin_login` as thin wrappers —
tests patch those names.

## 2. Page discovery — `proofcms/core/crawl.py`

```python
from ...core.crawl import crawl_pages, rest_list_links, extract_links
pages = crawl_pages(lambda u: sess.get(u, timeout=8), base,
                    common_paths=COMMON_PATHS, max_pages=12, skip_markers=SKIP_LINK_MARKERS)
pages = rest_list_links(lambda u: request(u, timeout=t, proxy=p), base, route="/wp/v2/pages", per_page=50)
```

Seeds + same-site homepage crawl, or REST listing. Field parsers stay local.

## 3. Aggressive args — `proofcms/core/args.py`

```python
# check(..., aggressive_command=None, aggressive_args=None, ...)
val = aggressive_value(aggressive_args, aggressive_command, "key", default)
```

New probes read named keys; legacy strings are fallback only. Document keys
in `--aggressive-arg` help. Established keys: `admin_user`,
`admin_password`, `canary_url`, `cache_group`, `page_url`, `username`,
`hash`, `full`, `form_url`, `file_hash`/`file_hashes`, `folder`, `file`,
`token`.

## 4. Transcripts — `proofcms/core/transcript.py`

`HttpClient` records `{method, url (user info scrubbed), status, body_len,
body_hash}` per exchange; stateless `request()` keeps a bounded thread-local
ring. Never bodies. Attach on VULNERABLE findings:

```python
evidence = attach_transcript({...}, sess)          # session client
evidence = attach_transcript({...}, take_transcript())  # stateless request()
# or: evidence_from(result, extra, transcript=[...])
```

Flows through `evidence` into JSON/text reports (redaction already handles
it). Drain the ring first in tests (`take_transcript()` before recording).

## 5. Lab cleanup — `proofcms/core/cleanup.py`

Opt in with (exact-arg preferred, pattern-sweep fallback, `manual` for what
HTTP cannot delete):

```python
def cleanup(target_url, *, timeout=12, proxy=None, aggressive_args=None, aggressive_command=None):
    from ...core.cleanup import cleanup_result
    ...
    return cleanup_result(removed=[...], remaining=[...], manual=[...])
```

`proofcms --lab-cleanup CVE -u URL` runs it (auth flags required, exit 2 if
anything remains). In-probe evidence should record what cleanup needs
(e.g. 18781's `delete_token`); the CLI lists hook-capable CVEs when the
requested one has no hook.
