from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import quote

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe, version_in_specifier

CVE_ID = "CVE-2026-102426"
NAME = "SP Page Builder Dynamic Content Filter reflected XSS"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder Pro 3.0.0 through 5.6.1p2"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    if version and str(version).strip().lower() == "5.6.1p2":
        return "LIKELY_VULNERABLE"
    if parse_version_safe(version) is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if version_in_specifier(version, ">=3.0.0,<=5.6.1") else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    detail = f"Detected SP Page Builder {version}, within the affected range." if status == "LIKELY_VULNERABLE" else f"Detected SP Page Builder {version}, outside the affected range." if status == "NOT_AFFECTED" else "SP Page Builder was detected, but its version could not be determined."
    action = "Upgrade SP Page Builder Pro to a fixed release and review Dynamic Content Filter pages." if status in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"} else "No action is required for this CVE when version detection is accurate."
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if status != "DETECTED_VERSION_UNKNOWN" else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    marker = f"PROOFCMS_DCF_{secrets.token_hex(6)}"
    payload = quote(f"l-r<{marker}>")
    url = f"{normalize_url(target_url)}/?dc_filter_probe={payload}"
    response = request(url, timeout=timeout, proxy=proxy)
    body = str(response.get("body", ""))
    if marker in body and f"&lt;{marker}&gt;" not in body:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The harmless Dynamic Content Filter marker was reflected as raw HTML. No script payload was sent.", action="Upgrade SP Page Builder Pro to a fixed release and remove the affected filter surface.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The safe Dynamic Content Filter marker was not reflected as raw HTML; no XSS was confirmed.", action="Upgrade affected SP Page Builder Pro versions even when external proof is inconclusive.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check or exploit_mode != "safe" or passive.status != "LIKELY_VULNERABLE":
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.0.0", "last_reviewed": "2026-10-14", "updated": "2026-10-14", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102426", "https://www.joomshaper.com/joomla-extensions/sp-page-builder-pro"]}
