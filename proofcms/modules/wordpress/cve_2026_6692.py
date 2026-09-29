from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .plugin_advisory import passive_only_check, passive_plugin_finding

CVE_ID = "CVE-2026-6692"
NAME = "Slider Revolution authenticated arbitrary file upload"
COMPONENT = "WordPress plugin Slider Revolution"
AFFECTED_RULE = "Slider Revolution 7.0.0 through 7.0.10; fixed in 7.0.11"
PLUGIN_SLUG = "revslider"
MINIMUM_VERSION = "7.0.0"
PATCHED_VERSION = "7.0.11"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    minimum = parse_version_safe(MINIMUM_VERSION)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or minimum is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < minimum:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    finding = passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade Slider Revolution to 7.0.11 or newer and review files uploaded by low-privilege users.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": [">=7.0.0,<=7.0.10"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-6692",
            "https://www.broadcom.com/support/security-center/protection-bulletin/cve-2026-6692-slider-revolution-plugin-vulnerability",
        ],
    }
