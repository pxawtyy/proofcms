from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .advisory import passive_component_finding, passive_only_check

CVE_ID = "CVE-2026-61424"
NAME = "DJ-Classifieds unauthenticated arbitrary file upload"
COMPONENT = "DJ-Classifieds"
AFFECTED_RULE = "DJ-Classifieds before 3.11.2"
DETECTOR_KEY = "djclassifieds"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < parse_version_safe("3.11.2") else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    finding = passive_component_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        detector_key=DETECTOR_KEY,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade DJ-Classifieds to 3.11.2 or newer and inspect its upload directories for executable files.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [DETECTOR_KEY],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-61424",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-61424",
        ],
    }
