from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .advisory import passive_component_finding, passive_only_check

CVE_ID = "CVE-2025-26854"
NAME = "Articles Good Search unauthenticated SQL injection"
COMPONENT = "Articles Good Search"
AFFECTED_RULE = "Articles Good Search 1.0.0 through 1.2.4.0011"
DETECTOR_KEY = "articles_good_search"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    minimum = parse_version_safe("1.0.0")
    maximum = parse_version_safe("1.2.4.0011")
    return "LIKELY_VULNERABLE" if minimum <= parsed <= maximum else "NOT_AFFECTED"


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
        remediation="Replace the affected release with a vendor-confirmed unaffected version and rotate database credentials if exploitation is suspected.",
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
            "https://www.cve.org/CVERecord?id=CVE-2025-26854",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-26854",
        ],
    }
