from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2018-11323"
NAME = "Joomla core ACL violation in access levels"
AFFECTED_RULE = "Joomla 2.5.0 through 3.8.7 (access levels of higher-permission groups)"
REMEDIATION = "Upgrade to Joomla 3.8.8 or a newer supported release and review user group access levels."


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("2.5.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("3.8.8") else "PATCHED"


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
            " An active proof needs an authenticated account able to manage user groups and "
            "access levels; the public surface does not disclose that state."
        )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["2.5.0-3.8.7"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": "Improper Access Control",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2018-11323",
            "https://developer.joomla.org/security-centre/729-20180501-core-acl-violation-in-access-levels.html",
        ],
    }
