from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient
from ...core.models import Confidence, Status
from .aspnet_legacy_common import legacy_passive

CVE_ID = "CVE-2011-3416"
NAME = "ASP.NET Forms Authentication null-byte bypass (MS11-100)"
RULE = "ASP.NET 1.1 SP1, 2.0 SP2, 3.5 SP1, 3.5.1, and 4.0 without MS11-100"
TYPE = "Authentication Bypass"
CVSS = "9.0"
_ASPXAUTH = re.compile(r"\.ASPXAUTH", re.IGNORECASE)
_FORMS = re.compile(r"FormsAuthentication|__VIEWSTATE|__EVENTVALIDATION", re.IGNORECASE)
_GX_SSO = re.compile(r"GX_AUTH|GX_SESSION_ID|gxcfg\.js|microsoftonline|GXState", re.IGNORECASE)
_SURFACE_PATHS = ("/", "/login.aspx", "/default.aspx", "/app.aspx", "/applogin.aspx")


def _auth_surface(client: HttpClient, timeout: int) -> dict[str, Any]:
    surface: dict[str, Any] = {
        "forms_auth": False,
        "genexus_sso": False,
        "aspnet_auth_cookie": False,
        "path": None,
    }
    for path in _SURFACE_PATHS:
        page = client.get(path, timeout=timeout)
        headers = {str(key).lower(): str(value) for key, value in (page.get("headers") or {}).items()}
        body = str(page.get("body") or "")
        set_cookie = headers.get("set-cookie", "")
        if _ASPXAUTH.search(set_cookie):
            return {
                "forms_auth": True,
                "genexus_sso": bool(_GX_SSO.search(body)),
                "aspnet_auth_cookie": True,
                "path": path,
            }
        if _FORMS.search(body) and not _GX_SSO.search(body):
            surface.update(forms_auth=True, path=path, aspnet_auth_cookie=False)
        if _GX_SSO.search(body) or "GX_SESSION_ID" in set_cookie:
            surface["genexus_sso"] = True
            surface["path"] = surface["path"] or path
    return surface


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aspnet_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del cms_version, exploit_mode, kwargs
    runtime = aspnet_runtime or {}
    finding = legacy_passive(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        aspnet_runtime=runtime,
        detail=(
            "MS11-100: if the patch is not installed, the Forms Authentication ticket parser can be "
            "bypassed with a crafted null-byte username, allowing access to another account such as "
            "an administrator."
        ),
        remediation="Install MS11-100 or upgrade off .NET Framework 2.0; rotate Forms Authentication machineKey.",
        vulnerability_type=TYPE,
        cvss=CVSS,
    )
    if finding.status != Status.LIKELY_VULNERABLE:
        return finding

    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    surface = _auth_surface(client, timeout)
    if not surface["forms_auth"]:
        finding.status = Status.NOT_AFFECTED
        finding.confidence = Confidence.HIGH
        finding.detail += (
            f" No .ASPXAUTH cookie, FormsAuthentication marker, or __VIEWSTATE login form was found "
            f"on {', '.join(_SURFACE_PATHS)}."
        )
        if surface["genexus_sso"]:
            finding.detail += (
                " The target uses GeneXus SSO (GX_* cookies/GXState), not Forms Authentication, "
                "so the MS11-100 Forms Authentication bypass does not apply."
            )
        else:
            finding.detail += (
                " Without a Forms Authentication login surface, the MS11-100 bypass does not apply."
            )
        return finding

    finding.confidence = Confidence.HIGH
    finding.evidence = {
        "auth_path": surface["path"],
        "aspnet_auth_cookie": surface["aspnet_auth_cookie"],
    }
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
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2011-3416",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-100",
        ],
    }
