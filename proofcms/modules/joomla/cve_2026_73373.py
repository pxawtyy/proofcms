from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2026-73373"
NAME = "Joomla unrestricted SHTML upload"
AFFECTED_RULE = "Joomla 1.0.0-5.4.7 and 6.0.0-6.1.2"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_safe("1.0.0") <= parsed < parse_version_safe("5.4.8"):
        return "LIKELY_VULNERABLE"
    if parse_version_safe("6.0.0") <= parsed < parse_version_safe("6.1.3"):
        return "LIKELY_VULNERABLE"
    if parsed >= parse_version_safe("5.4.8"):
        return "PATCHED"
    return "NOT_AFFECTED"


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
        remediation="Upgrade to Joomla 5.4.8, 6.1.3, or newer and inspect writable media directories for SHTML files.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=1.0.0,<5.4.8", ">=6.0.0,<6.1.3"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-73373",
            "https://developer.joomla.org/security-centre/1077-20260810-core-unrestricted-uploads-of-shtml-files.html",
        ],
    }
