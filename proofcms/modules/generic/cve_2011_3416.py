from __future__ import annotations

from typing import Any

from .aspnet_legacy_common import legacy_passive

CVE_ID = "CVE-2011-3416"
NAME = "ASP.NET Forms Authentication null-byte bypass (MS11-100)"
RULE = "ASP.NET 1.1 SP1, 2.0 SP2, 3.5 SP1, 3.5.1, and 4.0 without MS11-100"
TYPE = "Authentication Bypass"
CVSS = "9.0"


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    aspnet_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del target_url, cms_version, kwargs
    finding = legacy_passive(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        aspnet_runtime=aspnet_runtime,
        detail=(
            "MS11-100: if the patch is not installed, the Forms Authentication ticket parser can be "
            "bypassed with a crafted null-byte username, allowing access to another account such as "
            "an administrator."
        ),
        remediation="Install MS11-100 or upgrade off .NET Framework 2.0; rotate Forms Authentication machineKey.",
        vulnerability_type=TYPE,
        cvss=CVSS,
    )
    if run_exploit_check:
        finding.detail += " This module is passive-only; no login-bypass request is sent."
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET/.NET Framework",
        "affected_rule": RULE,
        "affected_versions": [".NET 1.1 SP1", ".NET 2.0 SP2", ".NET 3.5 SP1", ".NET 3.5.1", ".NET 4.0"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2011-3416",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-100",
        ],
    }
