from __future__ import annotations

import re
from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-105606"
NAME = "Custom Tables unauthenticated file upload"
COMPONENT = "Custom Tables"
AFFECTED_RULE = "Custom Tables 1.0 through 3.7.7; fixed in 3.7.8"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("3.7.8")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("customtables", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=False, detail="Custom Tables was not detected through its manifest or component route.", action="No action is required unless Custom Tables is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Custom Tables {version}, within the affected range below 3.7.8. A public submission form with a file field can accept a polyglot upload into the web-accessible temporary directory."
        action = "Upgrade Custom Tables to 3.7.8 or newer and remove unexpected files from the temporary upload directory."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Custom Tables {version}, which sanitises the temporary file name and path before saving."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Custom Tables was detected, but its version could not be determined."
        action = "Determine the installed Custom Tables version and upgrade to 3.7.8 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=False, detail=detail, action=action)


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    del target_url, joomla_version, run_exploit_check, timeout, proxy, exploit_mode, aggressive_command, aggressive_args, kwargs
    return passive_result(plugins)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": False, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Unrestricted File Upload", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["customtables"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-105606", "https://joomlaboat.com", "https://github.com/joomlaboat/custom-tables"]}
