from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2012-1563"
NAME = "Joomla core privilege escalation via registration state"
AFFECTED_RULE = "Joomla 1.6.x, 1.7.x and 2.5.0 through 2.5.2"
REMEDIATION = "Upgrade to Joomla 2.5.3 or a newer supported release and disable registration if unused."


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("1.6.0"):
        return "NOT_AFFECTED"
    if parsed < parse_version_required("2.0.0"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("2.5.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("2.5.3") else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    **kwargs: Any,
) -> Any:
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    if joomla_version and finding.status == "LIKELY_VULNERABLE":
        finding.detail += (
            " An active proof needs public registration and a crafted registration state; no "
            "safe unauthenticated probe is available."
        )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["1.6.0-1.7.5", "2.5.0-2.5.2"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": "Privilege Escalation",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2012-1563",
            "https://developer.joomla.org/security-centre/395-20120303-core-privilege-escalation.html",
        ],
    }
