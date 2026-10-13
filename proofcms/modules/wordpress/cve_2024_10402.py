from __future__ import annotations

from typing import Any

from ...core.models import Finding
from .forminator_advisory import COMPONENT, blocked_finding, passive_result

CVE_ID = "CVE-2024-10402"
NAME = "Forminator authenticated contributor form creation/update authorization bypass"
AFFECTED_RULE = "Forminator <=1.35.1; fixed in 1.36.0"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    from .forminator_advisory import classify_version as classify

    return classify(version, fixed="1.36.0")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    return blocked_finding(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, detail="The advisory requires an authenticated Contributor-level session and a form create/update request. No credentialed session was supplied, so the safe probe sent no state-changing request.", action="Upgrade Forminator to 1.36.0 or newer; if an authorized staging account is available, test capability enforcement there.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins, fixed="1.36.0", remediation="Upgrade Forminator to 1.36.0 or newer.")
    if not run_exploit_check or exploit_mode != "safe" or passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=1.35.1"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.0.0", "last_reviewed": "2026-10-12", "updated": "2026-10-12", "required_detectors": ["detect_wordpress_plugins"], "references": ["https://www.cve.org/CVERecord?id=CVE-2024-10402", "https://plugins.trac.wordpress.org/changeset/3169243/", "https://www.wordfence.com/threat-intel/vulnerabilities/id/be1d9d2b-cbdf-4d62-85fe-2616eaf02848"]}
