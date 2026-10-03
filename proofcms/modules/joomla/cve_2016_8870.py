from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .advisory import passive_core_finding
from .registration_probe import submit_registration

CVE_ID = "CVE-2016-8870"
NAME = "Joomla disabled-registration account creation"
AFFECTED_RULE = "Joomla 3.4.4 through 3.6.3"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_safe("3.4.4"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_safe("3.6.4") else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade Joomla to 3.6.4 or a currently supported release and audit unexpected users.",
    )
    finding.exploit_available = True
    if not run_exploit_check or finding.status != "LIKELY_VULNERABLE":
        return finding
    if exploit_mode != "aggressive":
        finding.detail += " Account creation is mutating and is available only in aggressive mode."
        return finding
    proof = submit_registration(target_url, group=None, timeout=timeout, proxy=proxy)
    finding.exploit_ran = proof["sent"]
    finding.proof_url = proof["proof_url"]
    if not proof["sent"]:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "LOW"
        finding.detail = proof["reason"]
    elif proof.get("frontend_login_verified") or proof.get("login_verified"):
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.detail = (
            "The generated account successfully authenticated to Joomla administrator, confirming that the legacy "
            f"registration request created a usable account. Disposable account: {proof['username']} / "
            f"{proof['password']} ({proof['email']})."
        )
    elif proof["accepted"]:
        finding.status = "AGGRESSIVE_SENT"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The legacy user.register request was sent and produced no explicit rejection, but its redirect/status "
            "is not evidence of account creation. "
            f"Disposable account candidate: {proof['username']} / {proof['password']} ({proof['email']}). "
            f"Login was not verified; candidate/control response differential="
            f"{proof.get('account_response_differential', False)}."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = f"The legacy registration request was rejected (HTTP {proof['status']})."
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=3.4.4,<3.6.4"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "module_version": "1.1.0",
        "last_reviewed": "2026-10-03",
        "updated": "2026-10-03",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2016-8870",
            "https://developer.joomla.org/security-centre/659-20161001-core-account-creation.html",
        ],
    }
