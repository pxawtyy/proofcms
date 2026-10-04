from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_only_check, passive_plugin_finding

CVE_ID = "CVE-2023-3460"
NAME = "Ultimate Member unauthenticated privilege escalation"
COMPONENT = "WordPress plugin Ultimate Member"
AFFECTED_RULE = "Ultimate Member before 2.6.7"
PLUGIN_SLUG = "ultimate-member"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("2.6.7") else "PATCHED"


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
        remediation="Upgrade Ultimate Member to 2.6.7 or newer and audit recently created privileged accounts.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["<2.6.7"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": ["https://www.cve.org/CVERecord?id=CVE-2023-3460"],
    }
