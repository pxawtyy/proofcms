from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_safe
from .plugin_advisory import passive_only_check, passive_plugin_finding

CVE_ID = "CVE-2024-6220"
RULE = "Keydatas through 2.5.2"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if value <= parse_version_safe("2.5.2") else "PATCHED"


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          plugins: dict[str, Any] | None = None, **kwargs: Any):
    finding = passive_plugin_finding(
        cve=CVE_ID, name="Keydatas unauthenticated arbitrary file upload",
        component="WordPress plugin Keydatas", affected_rule=RULE, plugin_slug="keydatas", plugins=plugins,
        classify=classify_version,
        remediation="Upgrade Keydatas beyond 2.5.2, rotate its publishing password, and inspect WordPress uploads for unexpected files.",
    )
    if finding.status == "LIKELY_VULNERABLE":
        finding.detail += " The affected source constructs image download paths from attacker-controlled URL segments; no upload request was sent because the publishing password and callback source are deployment-specific."
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": "Keydatas unauthenticated arbitrary file upload",
            "component": "WordPress plugin Keydatas", "affected_rule": RULE, "affected_versions": ["<=2.5.2"],
            "exploit_available": False, "exploit_modes": [], "intrusive": False,
            "references": ["https://plugins.trac.wordpress.org/changeset/3127334/keydatas", "https://nvd.nist.gov/vuln/detail/CVE-2024-6220"]}
