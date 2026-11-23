from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status


def core_runtime_gate(
    *,
    cve: str,
    name: str,
    rule: str,
    component: str,
    vulnerability_type: str,
    aspnet_runtime: dict[str, Any] | None,
    exploit_available: bool = False,
) -> Finding | None:
    """Return a terminal finding when the target is not an ASP.NET Core host.

    ``ASP.NET_SessionId`` and ``X-AspNet-Version`` are classic ASP.NET/IIS
    markers. Core-only advisories must not inherit them, otherwise a classic
    ``.aspx`` site is reported as "detected, version unknown" for
    Kestrel/Blazor/SignalR/DataProtection.
    """
    runtime = aspnet_runtime or {}
    if not runtime.get("detected"):
        return Finding(
            cve=cve,
            name=name,
            status=Status.NOT_DETECTED,
            confidence=Confidence.MEDIUM,
            component=component,
            affected_rule=rule,
            exploit_available=exploit_available,
            detail=f"{component} was not detected on the target; no runtime version was evaluated.",
            action="No action is required unless the target is served by ASP.NET Core.",
            vulnerability_type=vulnerability_type,
        )
    if runtime.get("core_detected"):
        return None
    return Finding(
        cve=cve,
        name=name,
        status=Status.NOT_AFFECTED,
        confidence=Confidence.HIGH,
        component=component,
        affected_rule=rule,
        exploit_available=exploit_available,
        detail=(
            "Classic ASP.NET/.NET Framework was fingerprinted, but no ASP.NET Core/Kestrel "
            "evidence was observed. This advisory targets ASP.NET Core and is not applicable "
            "to the detected runtime."
        ),
        action="No action is required for this CVE on the detected runtime.",
        evidence={
            "source": runtime.get("source"),
            "core_source": runtime.get("core_source") or "not-detected",
        },
        vulnerability_type=vulnerability_type,
    )


def runtime_finding(
    *,
    cve: str,
    name: str,
    rule: str,
    vulnerability_type: str,
    remediation: str,
    aspnet_runtime: dict[str, Any] | None,
) -> Finding:
    runtime = aspnet_runtime or {}
    if not runtime.get("detected"):
        return Finding(
            cve,
            name,
            Status.NOT_DETECTED,
            Confidence.LOW,
            "ASP.NET runtime",
            affected_rule=rule,
            detail="ASP.NET was not fingerprinted from public HTTP responses.",
            action=remediation,
            vulnerability_type=vulnerability_type,
        )
    version = runtime.get("version")
    core_detected = bool(runtime.get("core_detected"))
    if core_detected and not version:
        return Finding(
            cve,
            name,
            Status.NOT_AFFECTED,
            Confidence.HIGH,
            "ASP.NET runtime",
            affected_rule=rule,
            detail=(
                "ASP.NET Core was fingerprinted without a .NET Framework version. This advisory "
                "targets the .NET Framework, which is not the runtime in use."
            ),
            action=remediation,
            evidence={
                "source": runtime.get("source"),
                "core_source": runtime.get("core_source") or "not-detected",
                "session_cookie": bool(runtime.get("session_cookie")),
            },
            vulnerability_type=vulnerability_type,
        )
    is_legacy = str(version or "").startswith(("2.0.", "3.0.", "3.5"))
    if not version:
        status = Status.INCONCLUSIVE
        confidence = Confidence.MEDIUM
        detail = (
            "ASP.NET was detected, but the public fingerprint did not expose the .NET Framework "
            "version; the affected branch and servicing build cannot be established."
        )
    elif is_legacy:
        status = Status.NOT_CONFIRMED
        confidence = Confidence.MEDIUM
        detail = (
            f"ASP.NET {version or 'legacy branch'} was disclosed publicly. The response does not expose the exact "
            "servicing build, operating-system prerequisite, or private configuration required to establish this CVE."
        )
    elif str(version).startswith("4."):
        status = Status.INCONCLUSIVE
        confidence = Confidence.MEDIUM
        detail = (
            f"ASP.NET {version} identifies the .NET Framework 4.x branch, which this advisory "
            "lists. The exact servicing build and patch level are not observable over HTTP, so "
            "the public version evidence cannot resolve the CVE."
        )
    else:
        status = Status.INCONCLUSIVE
        confidence = Confidence.MEDIUM
        detail = (
            f"ASP.NET {version} was detected outside the legacy 2.0/3.x branches. The exact "
            "servicing build and patch level are not observable over HTTP."
        )
    return Finding(
        cve,
        name,
        status,
        confidence,
        "ASP.NET runtime",
        version,
        rule,
        detail=detail,
        action=remediation,
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "session_cookie": bool(runtime.get("session_cookie")),
            "core_detected": core_detected,
            "core_source": runtime.get("core_source") or "not-detected",
            "exact_servicing_build_observable": False,
        },
        vulnerability_type=vulnerability_type,
    )


def metadata(
    *,
    cve: str,
    name: str,
    component: str,
    rule: str,
    vulnerability_type: str,
    references: list[str],
) -> dict[str, Any]:
    return {
        "cve": cve,
        "cms": "generic",
        "name": name,
        "component": component,
        "affected_rule": rule,
        "affected_versions": ["ASP.NET/.NET Framework 2.0–3.5 legacy branches; exact OS/build varies"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": vulnerability_type,
        "required_detectors": ["aspnet"],
        "references": references,
    }
