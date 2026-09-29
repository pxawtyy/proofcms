from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .plugin_advisory import passive_only_check, passive_plugin_finding

CVE_ID = "CVE-2026-18781"
NAME = "Drag and Drop Multiple File Upload for CF7 filename validation bypass"
COMPONENT = "WordPress plugin Drag and Drop Multiple File Upload for Contact Form 7"
AFFECTED_RULE = "Drag and Drop Multiple File Upload for Contact Form 7 before 1.3.9.9"
PLUGIN_SLUG = "drag-and-drop-multiple-file-upload-contact-form-7"
PATCHED_VERSION = "1.3.9.9"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
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
        remediation="Upgrade the Drag and Drop Multiple File Upload for CF7 plugin to 1.3.9.9 or newer and review uploaded files.",
    )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["<1.3.9.9"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-18781",
            "https://wpscan.com/vulnerability/fb59519b-80ae-48e4-a31a-71d24ded205b/",
        ],
    }
