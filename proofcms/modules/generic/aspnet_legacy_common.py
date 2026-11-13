from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status


def is_netfx2(aspnet_runtime: dict[str, Any] | None) -> bool:
    runtime = aspnet_runtime or {}
    return bool(runtime.get("detected")) and str(runtime.get("version") or "").startswith("2.0.50727")


def legacy_passive(
    *,
    cve: str,
    name: str,
    rule: str,
    aspnet_runtime: dict[str, Any] | None,
    detail: str,
    remediation: str,
    vulnerability_type: str,
    cvss: str,
) -> Finding:
    runtime = aspnet_runtime or {}
    if not runtime.get("detected"):
        return Finding(
            cve=cve,
            name=name,
            status=Status.NOT_DETECTED,
            confidence=Confidence.LOW,
            component="ASP.NET/.NET Framework",
            affected_rule=rule,
            exploit_available=False,
            detail="ASP.NET was not fingerprinted from public HTTP responses.",
            action="Verify the IIS/.NET Framework build from an authenticated host inventory.",
            vulnerability_type=vulnerability_type,
        )
    version = runtime.get("version")
    if not version:
        return Finding(
            cve=cve,
            name=name,
            status=Status.INCONCLUSIVE,
            confidence=Confidence.MEDIUM,
            component="ASP.NET/.NET Framework",
            affected_rule=rule,
            exploit_available=False,
            detail=(
                "ASP.NET was detected, but the runtime version was not exposed in public responses; "
                "the .NET Framework branch cannot be established from headers alone."
            ),
            action=remediation,
            vulnerability_type=vulnerability_type,
        )
    if is_netfx2(runtime):
        return Finding(
            cve=cve,
            name=name,
            status=Status.LIKELY_VULNERABLE,
            confidence=Confidence.HIGH,
            component="ASP.NET/.NET Framework",
            component_version=version,
            affected_rule=rule,
            exploit_available=False,
            detail=f"ASP.NET {version} is the end-of-life .NET Framework 2.0 runtime. {detail} (CVSS {cvss})",
            action=remediation,
            vulnerability_type=vulnerability_type,
        )
    return Finding(
        cve=cve,
        name=name,
        status=Status.INCONCLUSIVE,
        confidence=Confidence.MEDIUM,
        component="ASP.NET/.NET Framework",
        component_version=version,
        affected_rule=rule,
        exploit_available=False,
        detail=(
            f"ASP.NET {version} is outside the .NET Framework 2.0 branch; confirm the exact servicing "
            "build and patch level on the host."
        ),
        action=remediation,
        vulnerability_type=vulnerability_type,
    )
