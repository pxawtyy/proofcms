from __future__ import annotations

from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe, version_lte

CVE_ID = "CVE-2026-57829"
NAME = "Helix Ultimate unauthenticated stored XSS"
COMPONENT = "Helix Ultimate Framework"
AFFECTED_RULE = "Helix Ultimate 1.0 through 2.2.6; fixed in 2.2.7"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if version_lte(version, "2.2.6") else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("helixultimate", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Helix Ultimate was not detected.", action="No action is required unless Helix Ultimate is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Helix Ultimate {version}, within the affected range."
        action = "Upgrade Helix Ultimate to 2.2.7 or newer and inspect menu parameters for unexpected markup."
    elif status == "NOT_AFFECTED":
        detail = f"Detected Helix Ultimate {version}, outside the affected range."
        action = "No action is required for this CVE when version detection is accurate."
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed Helix Ultimate version and upgrade to 2.2.7 or newer."
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if status != "DETECTED_VERSION_UNKNOWN" else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    url = f"{normalize_url(target_url)}/index.php?option=com_ajax&plugin=helixultimate&format=json&task=saveMegaMenuSettings"
    response = request(url, timeout=timeout, proxy=proxy)
    status = int(response.get("status", 0))
    if status in {404, 410} or response.get("redirected"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Helix AJAX task was not publicly reachable; the stored-XSS write path could not be tested.", action="Upgrade affected versions and verify the Helix AJAX dispatcher on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Helix AJAX dispatcher responded (HTTP {status}), but proving stored XSS requires a state-changing menu write and subsequent page load. The safe probe sent no write payload.", action="Upgrade Helix Ultimate to 2.2.7 or newer; use the documented inert-marker PoC only on authorized staging data.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check or exploit_mode != "safe" or passive.status != "LIKELY_VULNERABLE":
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.0.0", "last_reviewed": "2026-10-14", "updated": "2026-10-14", "required_detectors": ["helixultimate"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-57829", "https://github.com/Is4yev/CVE-2026-57829", "https://github.com/advisories/GHSA-6r9m-9724-qfvg"]}
