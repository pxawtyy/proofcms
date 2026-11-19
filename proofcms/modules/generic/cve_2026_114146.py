from __future__ import annotations

import json
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-114146"
NAME = "ASP.NET Core SignalR connection identity binding bypass"
RULE = "Microsoft.AspNetCore.Http.Connections 1.2.0 through 1.2.13"
FIXED_RULE = "Upgrade Microsoft.AspNetCore.Http.Connections to 1.2.14 or later."
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []

_NEGOTIATE_PATHS = (
    "/hub/negotiate?negotiateVersion=1",
    "/signalr/negotiate?negotiateVersion=1",
    "/chat/negotiate?negotiateVersion=1",
    "/negotiate?negotiateVersion=1",
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("1.2.0"):
        return Status.NOT_AFFECTED
    if parsed < parse_version_required("1.2.14"):
        return Status.LIKELY_VULNERABLE
    if parsed < parse_version_required("2.0.0"):
        return Status.PATCHED
    # 8.x/9.x/10.x values are runtime versions, not the 1.2.x package.
    return Status.DETECTED_VERSION_UNKNOWN


def _signalr_surface(client: HttpClient, base: str, timeout: int) -> dict[str, Any] | None:
    for path in _NEGOTIATE_PATHS:
        response = client.get(f"{base}{path}", timeout=timeout)
        if is_transport_error(response):
            continue
        if response.get("status") != 200:
            continue
        body = response.get("body") or ""
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue
        if "connectionId" in parsed or "availableTransports" in parsed:
            return {
                "path": path,
                "status": 200,
                "connection_id": bool(parsed.get("connectionId")),
                "transports": len(parsed.get("availableTransports") or []),
            }
    return None


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    **kwargs: Any,
) -> Finding:
    del kwargs
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    surface = _signalr_surface(client, base, timeout)
    version = cms_version
    status = classify_version(version)

    if surface is None and not version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_DETECTED,
            confidence=Confidence.MEDIUM,
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                "No SignalR negotiate endpoint was observed on the common paths, and no "
                "Microsoft.AspNetCore.Http.Connections package version was supplied. The probe "
                "only reads the negotiate routes; it does not open a Hub connection."
            ),
            action="Provide the package version or point the probe at the SignalR negotiate route.",
        )

    evidence = {"surface": surface, "version": version}

    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Microsoft.AspNetCore.Http.Connections {version} is in the affected 1.2.0-1.2.13 range. "
            "The public issue is an identity-binding error: messages injected after negotiation can "
            "run Hub invocations as the victim. The active proof needs a SignalR client and a second "
            "identity, so no connection is opened."
        )
        confidence = Confidence.HIGH if surface else Confidence.MEDIUM
        action = FIXED_RULE
    elif status == Status.PATCHED:
        detail = f"Microsoft.AspNetCore.Http.Connections {version} is at or beyond the fixed 1.2.14 release."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE if the package version is accurate."
    elif status == Status.NOT_AFFECTED:
        detail = f"Microsoft.AspNetCore.Http.Connections {version} is older than 1.2.0 and outside the affected range."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE."
    else:
        detail = (
            "The Microsoft.AspNetCore.Http.Connections package version could not be determined. "
            "A detected 8.x/9.x/10.x value is a runtime version, not the 1.2.x package."
        )
        confidence = Confidence.MEDIUM
        action = FIXED_RULE

    if run_exploit_check:
        detail += " This module is passive-only; no Hub connection or injected message is sent."

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="ASP.NET Core / SignalR",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=action,
        evidence=evidence,
        vulnerability_type="Incorrect Authorization",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET Core / SignalR",
        "affected_rule": RULE,
        "affected_versions": [">=1.2.0,<1.2.14"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Incorrect Authorization",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-19",
        "updated": "2026-11-19",
        "required_detectors": ["aspnet"],
        "references": [
            "https://github.com/advisories/GHSA-67wp-ghc2-fw2g",
            "https://advisories.gitlab.com/nuget/microsoft.aspnetcore.http.connections/CVE-2026-114146/",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-114146",
        ],
    }
