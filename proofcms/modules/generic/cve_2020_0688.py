from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2020-0688"
NAME = "Exchange ViewState deserialization (static machine key)"
RULE = (
    "Exchange 2010 SP3 before 14.3.468.3, 2013 before 15.0.1497.2, "
    "2016 before 15.1.1713.5, 2019 before 15.2.792.3"
)
FIXED_RULE = (
    "Install the February 2020 Exchange security updates "
    "(2010 SP3 RU30, 2013 CU23 SU, 2016 CU15 SU, 2019 CU4 SU)."
)
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN

    if parsed < parse_version_required("14.0.0"):
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("15.0.0"):
        return (
            Status.LIKELY_VULNERABLE
            if parsed < parse_version_required("14.3.468.3")
            else Status.PATCHED
        )
    if parsed < parse_version_required("15.1.0"):
        return (
            Status.LIKELY_VULNERABLE
            if parsed < parse_version_required("15.0.1497.2")
            else Status.PATCHED
        )
    if parsed < parse_version_required("15.2.0"):
        return (
            Status.LIKELY_VULNERABLE
            if parsed < parse_version_required("15.1.1713.5")
            else Status.PATCHED
        )
    if parsed < parse_version_required("15.3.0"):
        return (
            Status.LIKELY_VULNERABLE
            if parsed < parse_version_required("15.2.792.3")
            else Status.PATCHED
        )
    return Status.DETECTED_VERSION_UNKNOWN


def _header(headers: dict[str, Any] | None, name: str) -> str | None:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return None


def _owa_surface(client: HttpClient, base: str, timeout: int) -> dict[str, Any] | None:
    for path in ("/owa/", "/owa/auth/logon.aspx"):
        response = client.get(f"{base}{path}", timeout=timeout)
        if is_transport_error(response):
            continue
        body = response.get("body") or ""
        version = _header(response.get("headers"), "X-OWA-Version")
        surface = (
            "__VIEWSTATE" in body
            or "__VIEWSTATEGENERATOR" in body
            or "logon.aspx" in body.lower()
        )
        if version or surface:
            return {
                "path": path,
                "status": response.get("status"),
                "version": version,
                "surface": surface,
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
    surface = _owa_surface(client, base, timeout)
    version = cms_version or (surface or {}).get("version")

    if surface is None and not version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_DETECTED,
            confidence=Confidence.MEDIUM,
            component="Microsoft Exchange / ASP.NET ViewState",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                "No Exchange OWA surface or X-OWA-Version header was observed. "
                "The probe only reads the OWA paths; it does not attempt a ViewState payload."
            ),
            action="No action is required unless the target is an Exchange OWA endpoint hidden from this path.",
        )

    status = classify_version(version)
    evidence = {"surface": surface, "version": version}

    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Exchange OWA build {version} is before the February 2020 fix, and the logon "
            "surface exposes ViewState. The public issue uses a static machine key to forge "
            "__VIEWSTATE; the active proof needs a mailbox session and a gadget chain, so only "
            "the build and surface are reported."
        )
        confidence = Confidence.HIGH
        action = FIXED_RULE
    elif status == Status.PATCHED:
        detail = f"Exchange OWA build {version} is at or beyond the February 2020 fix."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE if the build is accurate."
    else:
        detail = (
            "An Exchange OWA/ViewState surface was observed, but the build could not be "
            "classified. Check X-OWA-Version or the Exchange build number."
        )
        confidence = Confidence.MEDIUM
        action = FIXED_RULE

    if run_exploit_check:
        detail += " This module is passive-only; no ViewState payload is sent."

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="Microsoft Exchange / ASP.NET ViewState",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=action,
        evidence=evidence,
        vulnerability_type="Deserialization of Untrusted Data",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "Microsoft Exchange / ASP.NET ViewState",
        "affected_rule": RULE,
        "affected_versions": [
            ">=14.0.0,<14.3.468.3",
            ">=15.0.0,<15.0.1497.2",
            ">=15.1.0,<15.1.1713.5",
            ">=15.2.0,<15.2.792.3",
        ],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Deserialization of Untrusted Data",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-19",
        "updated": "2026-11-19",
        "required_detectors": [],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-0688",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0688",
        ],
    }
