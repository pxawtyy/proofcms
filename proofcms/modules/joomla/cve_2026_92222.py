from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2026-92222"
NAME = "Joomla core extension SSRF vectors"
AFFECTED_RULE = "Joomla 3.0.0-5.4.8 and 6.0.0-6.1.3"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("3.0.0") <= parsed < parse_version_required("5.4.9"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.4"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("3.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


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
        remediation="Upgrade to Joomla 5.4.9, 6.1.4, or newer and restrict outbound web-server traffic.",
    )
    finding = passive_only_check(finding, run_exploit_check)
    if run_exploit_check and finding.status == "LIKELY_VULNERABLE":
        finding.detail += " No callback endpoint was supplied, so no server-side request was induced."
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=3.0.0,<5.4.9", ">=6.0.0,<6.1.4"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-03",
        "updated": "2026-10-03",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-92222",
            "https://developer.joomla.org/security-centre/1089-20260909-core-ssrf-vectors-in-various-core-extensions.html",
        ],
    }
