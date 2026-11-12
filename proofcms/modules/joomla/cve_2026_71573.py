from __future__ import annotations

import secrets
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2026-71573"
NAME = "Joomla improper CORS origin validation"
RULE = "Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 when CORS is enabled"
REMEDIATION = "Upgrade to Joomla 5.4.8, 6.1.3, or a newer supported release."
API_PATH = "/api/index.php/v1/content/articles"


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


def run_safe_probe(
    target_url: str,
    api_token: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Send a preflight and (with a fixture token) a credentialed API GET.

    The 5.4.7 ``respond()`` method reflects every request Origin in
    ``Access-Control-Allow-Origin`` together with
    ``Access-Control-Allow-Credentials: true``; 5.4.8 only reflects an
    Origin that appears in the configured whitelist. A token is needed
    because the API returns 401 (and skips ``respond()``) without one.
    """
    base = normalize_url(target_url)
    origin = f"https://proofcms-{secrets.token_hex(8)}.invalid"
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.request(
        f"{base}{API_PATH}",
        method="OPTIONS",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
        timeout=timeout,
        follow_redirects=False,
    )
    evidence: dict[str, Any] = {
        "probe_origin": origin,
        "preflight_status": preflight.get("status", 0),
        "preflight_allow_origin": _header(preflight, "access-control-allow-origin") or None,
    }
    if not api_token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{API_PATH}",
            evidence=evidence,
            detail=(
                "The CORS preflight was sent, but the API returns 401 without a token and the "
                "reflection only happens on a successful response. Re-run with "
                "--aggressive-arg api_token=... from the lab fixture."
            ),
            action=REMEDIATION,
            vulnerability_type="Improper CORS Validation",
        )

    response = client.request(
        f"{base}{API_PATH}",
        method="GET",
        headers={"Origin": origin, "Authorization": f"Bearer {api_token}"},
        timeout=timeout,
        follow_redirects=False,
    )
    allow_origin = _header(response, "access-control-allow-origin")
    allow_credentials = _header(response, "access-control-allow-credentials")
    evidence.update(
        {
            "api_status": response.get("status", 0),
            "access_control_allow_origin": allow_origin or None,
            "access_control_allow_credentials": allow_credentials or None,
        }
    )
    reflected = (
        response.get("status") == 200
        and allow_origin.rstrip("/") == origin
        and allow_credentials.lower() == "true"
    )
    if reflected:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{API_PATH}",
            evidence=evidence,
            detail=(
                "A successful API request carrying an untrusted Origin was answered with "
                "Access-Control-Allow-Origin set to that Origin and "
                "Access-Control-Allow-Credentials: true, bypassing the configured whitelist."
            ),
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
        proof_url=f"{base}{API_PATH}",
        evidence=evidence,
        detail=(
            "The API did not reflect the untrusted Origin with credentials "
            f"(status={response.get('status', 0)}, ACAO={allow_origin or 'absent'}, "
            f"ACAC={allow_credentials or 'absent'})."
        ),
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
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
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
        passive.detail += " This module supports only the safe CORS probe."
        return passive
    if passive.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        passive.detail += " Safe proof skipped because the detected Joomla release is not affected."
        return passive
    result = run_safe_probe(
        target_url,
        api_token=aggressive_value(aggressive_args, aggressive_command, "api_token"),
        timeout=timeout,
        proxy=proxy,
    )
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
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-12",
        "updated": "2026-11-12",
        "references": [
            "https://developer.joomla.org/security-centre/1069-20260802-core-improper-cors-origin-validation.html",
            "https://www.cve.org/CVERecord?id=CVE-2026-71573",
        ],
    }
