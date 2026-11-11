from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_only_check, passive_plugin_finding

CVE_ID = "CVE-2026-1830"
RULE = "Quick Playground through 1.3.1"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if value <= parse_version_required("1.3.1") else "PATCHED"


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          plugins: dict[str, Any] | None = None, **kwargs: Any):
    finding = passive_plugin_finding(
        cve=CVE_ID, name="Quick Playground unauthenticated arbitrary file upload",
        component="WordPress plugin Quick Playground", affected_rule=RULE, plugin_slug="quick-playground",
        plugins=plugins, classify=classify_version,
        remediation="Upgrade Quick Playground beyond 1.3.1 and inspect WordPress uploads for unexpected files.",
    )
    if finding.status == "LIKELY_VULNERABLE":
        finding.detail += (" No upload request was sent: on a stock install the plugin fatals the whole WordPress "
                           "bootstrap (is_plugin_active() called at plugins_loaded, undefined outside admin context), "
                           "so the vulnerable REST endpoint is unreachable without modifying the plugin.")
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": "Quick Playground unauthenticated arbitrary file upload",
            "component": "WordPress plugin Quick Playground", "affected_rule": RULE, "affected_versions": ["<=1.3.1"],
            "exploit_available": False, "exploit_modes": [], "intrusive": False,
            "references": ["https://www.exploit-db.com/exploits/52596", "https://nvd.nist.gov/vuln/detail/CVE-2026-1830"]}
