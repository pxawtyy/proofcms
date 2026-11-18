from __future__ import annotations

import re
from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe
from . import cve_2026_57829 as mega_menu

CVE_ID = "CVE-2026-78077"
NAME = "Helix Ultimate stored XSS in Mega Menu layout values"
COMPONENT = "Helix Ultimate (helixultimate)"
AFFECTED_RULE = "Helix Ultimate 1.0.0 through 2.2.9; fixed in 2.2.10"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.2.10")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("helixultimate", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Helix Ultimate was not detected through its manifest or template assets.", action="No action is required unless Helix Ultimate is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Helix Ultimate {version}, within the affected range below 2.2.10. Mega Menu layout values are stored and rendered without complete contextual escaping."
        action = "Upgrade Helix Ultimate to 2.2.10 or newer and inspect menu parameters for unexpected markup."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Helix Ultimate {version}, which sanitises the Mega Menu layout JSON."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed Helix Ultimate version and upgrade to 2.2.10 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    menu_item: int | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Reuse the Mega Menu stored-marker probe for the 2.2.10 layout fix.

    2.2.10 sanitises the Mega Menu layout JSON values that CVE-2026-78077
    covers; the write/read path is the same as CVE-2026-57829. The shared
    probe writes an inert quote marker, verifies it is rendered inside the
    menu attribute, and clears the layout key.
    """
    result = mega_menu.run_aggressive_probe(target_url, menu_item=menu_item, timeout=timeout, proxy=proxy)
    result.cve = CVE_ID
    result.name = NAME
    result.affected_rule = AFFECTED_RULE
    result.detail = (
        "The Mega Menu layout value was stored and rendered without complete contextual escaping; "
        "2.2.10 sanitises the layout JSON. " + result.detail
    )
    result.action = "Upgrade Helix Ultimate to 2.2.10 or newer and review stored menu parameters."
    return result


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    result = mega_menu.run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.cve = CVE_ID
    result.name = NAME
    result.affected_rule = AFFECTED_RULE
    return result


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Helix Ultimate was not detected as potentially affected."
            return passive
        menu_value = aggressive_value(aggressive_args, aggressive_command, "menuitem")
        result = run_aggressive_probe(
            target_url,
            menu_item=int(menu_value) if menu_value and menu_value.isdigit() else None,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (Mega Menu dispatcher reachability) and aggressive (stored marker) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Cross-Site Scripting (XSS)", "module_version": "1.0.0", "last_reviewed": "2026-11-17", "updated": "2026-11-17", "required_detectors": ["helixultimate"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-78077", "https://github.com/JoomShaper/helix-ultimate/releases/tag/v2.2.10", "https://mysites.guru/vulnerabilities/CVE-2026-78077/"]}
