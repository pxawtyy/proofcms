from __future__ import annotations

import re
from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-107904"
NAME = "Easy File Uploader unauthenticated remote code execution"
COMPONENT = "Easy File Uploader"
AFFECTED_RULE = "Easy File Uploader 1.0.0 through 2.9.6; fixed in 2.9.7"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.9.7")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("easyfileuploader", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=False, detail="Easy File Uploader was not detected through its module manifest.", action="No action is required unless Easy File Uploader is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Easy File Uploader {version}, within the affected range below 2.9.7. A public module instance accepts a multipart upload without authentication or a CSRF token."
        action = "Upgrade Easy File Uploader to 2.9.7 or newer and remove unexpected files from the configured upload folder."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Easy File Uploader {version}, which restricts the uploaded file type and destination."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Easy File Uploader was detected, but its version could not be determined."
        action = "Determine the installed Easy File Uploader version and upgrade to 2.9.7 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=False, detail=detail, action=action)


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    del target_url, joomla_version, run_exploit_check, timeout, proxy, exploit_mode, aggressive_command, aggressive_args, kwargs
    return passive_result(plugins)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": False, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["easyfileuploader"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-107904", "https://www.valorapps.com/", "https://github.com/ollily/easyfileuploader"]}
