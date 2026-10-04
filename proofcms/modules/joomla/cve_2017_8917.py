from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2017-8917"
NAME = "Joomla com_fields unauthenticated SQL injection"
AFFECTED_RULE = "Joomla 3.7.0"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    affected = parse_version_required("3.7.0")
    if parsed == affected:
        return "LIKELY_VULNERABLE"
    return "PATCHED" if parsed > affected else "NOT_AFFECTED"


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
        remediation="Upgrade Joomla 3.7.0 to 3.7.1 or a currently supported release immediately.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["==3.7.0"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2017-8917",
            "https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html",
        ],
    }
