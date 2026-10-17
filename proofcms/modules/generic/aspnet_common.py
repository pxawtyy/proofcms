from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status


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
    is_legacy = str(version or "").startswith(("2.0.", "3.0.", "3.5"))
    if is_legacy:
        status = Status.NOT_CONFIRMED
        confidence = Confidence.MEDIUM
        detail = (
            f"ASP.NET {version or 'legacy branch'} was disclosed publicly. The response does not expose the exact "
            "servicing build, operating-system prerequisite, or private configuration required to establish this CVE."
        )
    else:
        status = Status.DETECTED_VERSION_UNKNOWN
        confidence = Confidence.LOW
        detail = "ASP.NET was detected, but the public fingerprint is insufficient to establish this CVE's affected build range."
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
