from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_only_check, passive_plugin_finding

CVE_ID = "CVE-2023-32243"
NAME = "Essential Addons for Elementor unauthenticated privilege escalation"
COMPONENT = "WordPress plugin Essential Addons for Elementor"
AFFECTED_RULE = "Essential Addons for Elementor 5.4.0 through 5.7.1"
PLUGIN_SLUG = "essential-addons-for-elementor-lite"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < parse_version_required("5.4.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("5.7.2") else "PATCHED"


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
        remediation="Upgrade Essential Addons for Elementor to 5.7.2 or newer and audit administrator accounts.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": [">=5.4.0,<5.7.2"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": ["https://www.cve.org/CVERecord?id=CVE-2023-32243"],
    }
