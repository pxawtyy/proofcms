from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-40372"
NAME = "ASP.NET Core DataProtection signature verification bypass"
RULE = (
    "Microsoft.AspNetCore.DataProtection 10.0.0 through 10.0.6 on non-Windows "
    "when the NuGet asset is loaded"
)
FIXED_RULE = (
    "Upgrade Microsoft.AspNetCore.DataProtection to 10.0.7 or later and rotate "
    "the DataProtection key ring."
)
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []

_COOKIE_NAMES = (
    ".aspnetcore.cookies",
    ".aspnetcore.antiforgery",
    "identity.application",
    ".aspxauth",
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN

    if parsed < parse_version_required("10.0.0"):
        return Status.NOT_AFFECTED
    if parsed < parse_version_required("10.0.7"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def _protected_surface(client: HttpClient, base: str, timeout: int) -> dict[str, Any] | None:
    response = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(response):
        return None
    headers_multi = response.get("headers_multi") or {}
    cookies = [str(value) for value in headers_multi.get("set-cookie", [])]
    body = response.get("body") or ""
    surface = (
        any(any(name in cookie.lower() for name in _COOKIE_NAMES) for cookie in cookies)
        or "__RequestVerificationToken" in body
    )
    return {
        "status": response.get("status"),
        "surface": surface,
        "cookies": cookies[:5],
    }


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
    surface = _protected_surface(client, base, timeout)
    version = cms_version
    status = classify_version(version)

    if surface is None and not version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_DETECTED,
            confidence=Confidence.MEDIUM,
            component="ASP.NET Core / DataProtection",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                "No ASP.NET Core DataProtection surface (auth or antiforgery cookie) was observed, "
                "and no runtime/package version was supplied. The probe only reads the landing page."
            ),
            action="Provide the DataProtection package/runtime version or test a page that sets an auth cookie.",
        )

    evidence = {"surface": surface, "version": version}

    if status == Status.LIKELY_VULNERABLE:
        has_surface = bool(surface and surface.get("surface"))
        detail = (
            f"DataProtection {version} is in the affected 10.0.0-10.0.6 range. "
            + (
                "The landing page sets an ASP.NET Core auth/antiforgery cookie, so protected payloads are in use. "
                if has_surface
                else "No protected cookie was observed on the landing page; the package may still be loaded. "
            )
            + "The public issue is a signature-verification bypass (CWE-347); an active proof needs a "
            "padding-oracle style query loop and a forged payload, so none is sent."
        )
        confidence = Confidence.HIGH if has_surface else Confidence.MEDIUM
        action = FIXED_RULE
    elif status == Status.PATCHED:
        detail = f"DataProtection {version} is at or beyond the fixed 10.0.7 release."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE if the package/runtime version is accurate."
    elif status == Status.NOT_AFFECTED:
        detail = (
            f"DataProtection {version} is outside the affected 10.0.0-10.0.6 range. "
            "The 8.0 and 9.0 servicing branches are not affected."
        )
        confidence = Confidence.HIGH
        action = "No action is required for this CVE."
    else:
        detail = (
            "The DataProtection version could not be determined. The 10.0.0-10.0.6 package "
            "on non-Windows is affected when the NuGet asset is loaded."
        )
        confidence = Confidence.MEDIUM
        action = FIXED_RULE

    if run_exploit_check:
        detail += " This module is passive-only; no forged payload or oracle query is sent."

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="ASP.NET Core / DataProtection",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=action,
        evidence=evidence,
        vulnerability_type="Improper Verification of Cryptographic Signature",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET Core / DataProtection",
        "affected_rule": RULE,
        "affected_versions": [">=10.0.0,<=10.0.6"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Improper Verification of Cryptographic Signature",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-19",
        "updated": "2026-11-19",
        "required_detectors": ["aspnet"],
        "references": [
            "https://github.com/advisories/GHSA-9mv3-2cwr-p262",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-40372",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40372",
        ],
    }
