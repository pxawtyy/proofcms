from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-88092"
NAME = "ASP.NET Core Kestrel request smuggling (2026-88092)"
RULE = "ASP.NET Core 8.0 before 8.0.32, 9.0 before 9.0.21, 10.0 before 10.0.13, and 11.0 before 11.0.0-rc2"
FIXED_RULE = "Upgrade ASP.NET Core to 8.0.32, 9.0.21, 10.0.13, 11.0.0-rc2, or newer"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parse_version_required("8.0.0") <= parsed < parse_version_required("8.0.32"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("9.0.0") <= parsed < parse_version_required("9.0.21"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("10.0.0") <= parsed < parse_version_required("10.0.13"):
        return Status.LIKELY_VULNERABLE
    if version and version.lower().startswith("11.0.0-rc1"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    **kwargs: Any,
) -> Finding:
    del target_url, timeout, proxy, kwargs
    status = classify_version(cms_version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"ASP.NET Core {cms_version} is in the affected range. This is a different "
            "request-smuggling variant from CVE-2025-55315; its exact wire shape is not "
            "reduced to a safe differential, so only version evidence is reported."
        )
        confidence = Confidence.HIGH
    elif status == Status.PATCHED:
        detail = f"ASP.NET Core {cms_version} is at or beyond the fixed release."
        confidence = Confidence.HIGH
    else:
        detail = "ASP.NET Core was detected, but its exact runtime version is unknown."
        confidence = Confidence.MEDIUM
    if run_exploit_check:
        detail += " This module is passive-only; no smuggling request is sent."
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="ASP.NET Core / Kestrel",
        component_version=cms_version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=FIXED_RULE,
        vulnerability_type="HTTP Request Smuggling",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET Core / Kestrel",
        "affected_rule": RULE,
        "affected_versions": [">=8.0.0,<8.0.32", ">=9.0.0,<9.0.21", ">=10.0.0,<10.0.13", "11.0.0-rc1"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "HTTP Request Smuggling",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-88092",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-88092",
        ],
    }
