from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-102870"
NAME = "ASP.NET Core Blazor WebAssembly debugger code injection"
COMPONENT = "ASP.NET Core / Blazor WebAssembly debug proxy"
RULE = "ASP.NET Core 10.0.0 before 10.0.13 and 11.0.0-preview before 10.0.14, when the Blazor WebAssembly debug proxy evaluates attacker-controlled data"
FIXED_RULE = "Upgrade Microsoft.AspNetCore.Components.WebAssembly.Server to 10.0.13 / 10.0.14 or newer and disable the debug proxy in production"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("10.0.0") <= parsed < parse_version_required("10.0.13"):
        return "LIKELY_VULNERABLE"
    if version and version.lower().startswith("11.0.0-preview"):
        return "LIKELY_VULNERABLE"
    return "PATCHED"


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
    if status == "LIKELY_VULNERABLE":
        detail = (
            f"ASP.NET Core {cms_version} is in the affected range. Exploitation requires the Blazor "
            "WebAssembly debug proxy to be enabled and a debugger expression to evaluate "
            "attacker-controlled application data; it is not a generic remote web endpoint."
        )
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"ASP.NET Core {cms_version} is at or beyond the fixed Blazor WebAssembly server package."
        confidence = "HIGH"
    else:
        detail = "The ASP.NET Core / Blazor WebAssembly server package version could not be determined."
        confidence = "LOW"
    if run_exploit_check:
        detail += " This module is passive-only; no debugger expression is sent."
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=cms_version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=FIXED_RULE,
        vulnerability_type="Code Injection",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": RULE,
        "affected_versions": [">=10.0.0,<10.0.13", "11.0.0-preview"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Code Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-102870",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102870",
            "https://github.com/dotnet/announcements/issues/445",
        ],
    }
