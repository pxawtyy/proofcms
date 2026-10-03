from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2015-7857"
NAME = "Joomla core content history SQL injection"
AFFECTED_RULE = "Joomla 3.2.0 through 3.4.4"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_safe("3.2.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_safe("3.4.5") else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade Joomla to 3.4.5 or a currently supported release.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=3.2.0,<3.4.5"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-03",
        "updated": "2026-10-03",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2015-7857",
            "https://developer.joomla.org/security-centre/628-20151001-core-sql-injection.html",
        ],
    }
