from __future__ import annotations

import secrets
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2026-71573"
NAME = "Joomla improper CORS origin validation"
RULE = "Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 when CORS is enabled"
REMEDIATION = "Upgrade to Joomla 5.4.8, 6.1.3, or a newer supported release."


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.INCONCLUSIVE
    if parse_version_required("4.0.0") <= value < parse_version_required("5.4.8"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("6.0.0") <= value < parse_version_required("6.1.3"):
        return Status.LIKELY_VULNERABLE
    if value >= parse_version_required("4.0.0"):
        return Status.PATCHED
    return Status.NOT_AFFECTED


def _header(response: dict[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in (response.get("headers") or {}).items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    origin = f"https://proofcms-{secrets.token_hex(8)}.invalid"
    response = HttpClient(timeout=timeout, proxy=proxy).request(
        f"{base}/api/index.php/v1/content/articles",
        method="OPTIONS",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
        timeout=timeout,
        follow_redirects=False,
    )
    allowed_origin = _header(response, "access-control-allow-origin")
    evidence = {
        "status": response.get("status", 0),
        "probe_origin": origin,
        "access_control_allow_origin": allowed_origin or None,
        "access_control_allow_credentials": _header(response, "access-control-allow-credentials") or None,
    }
    if allowed_origin.rstrip("/") == origin:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}/api/index.php/v1/content/articles",
            evidence=evidence,
            detail="The Joomla API reflected a unique, untrusted Origin in Access-Control-Allow-Origin.",
            action=REMEDIATION,
            vulnerability_type="Improper CORS Validation",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="Joomla core",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}/api/index.php/v1/content/articles",
        evidence=evidence,
        detail="The API did not reflect the unique untrusted Origin; vulnerable CORS behavior was not confirmed.",
        action=REMEDIATION,
        vulnerability_type="Improper CORS Validation",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
) -> Finding:
    passive = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    passive.exploit_available = True
    passive.vulnerability_type = "Improper CORS Validation"
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the safe preflight probe."
        return passive
    if passive.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        passive.detail += " Safe proof skipped because the detected Joomla release is not affected."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = joomla_version
    return result


def affects_joomla_version(joomla_version: str | None) -> bool:
    return classify_version(joomla_version) in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": RULE,
        "affected_joomla_versions": [">=4.0.0,<5.4.8", ">=6.0.0,<6.1.3"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": "Improper CORS Validation",
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-09",
        "updated": "2026-10-09",
        "references": ["https://developer.joomla.org/security-centre.html"],
    }
