from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe


def acymailing_finding(
    *,
    cve: str,
    name: str,
    affected_rule: str,
    fixed_version: str,
    minimum_version: str | None = None,
    plugins: dict | None,
    enterprise_only: bool,
    remediation: str,
) -> Finding:
    info = (plugins or {}).get("acymailing", {})
    found = bool(info.get("found"))
    version = info.get("version")
    edition = str(info.get("edition") or "").lower()
    component = "AcyMailing Enterprise" if enterprise_only else "AcyMailing"

    if not found:
        return Finding(
            cve=cve,
            name=name,
            status="NOT_DETECTED",
            confidence="HIGH",
            component=component,
            affected_rule=affected_rule,
            detail="AcyMailing was not detected through its public component manifests or routes.",
            action="No public AcyMailing installation was detected; verify manually if access is restricted.",
        )

    parsed = parse_version_safe(version)
    fixed = parse_version_safe(fixed_version)
    minimum = parse_version_safe(minimum_version)
    if parsed is None:
        status, confidence = "DETECTED_VERSION_UNKNOWN", "MEDIUM"
        detail = "AcyMailing was detected, but its version could not be determined."
    elif minimum is not None and parsed < minimum:
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = f"Detected AcyMailing {version}, which predates the affected code introduced in {minimum_version}."
    elif parsed >= fixed:
        status, confidence = "PATCHED", "HIGH"
        detail = f"Detected AcyMailing {version}, which is at or above the fixed release {fixed_version}."
    elif enterprise_only and edition not in {"enterprise", "commercial", "pro"}:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = (
            f"Detected AcyMailing {version}, which is below {fixed_version}, but the public evidence did not confirm "
            "the Enterprise edition required by this CVE."
        )
    else:
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        edition_text = f" {edition.title()}" if edition else ""
        detail = f"Detected AcyMailing{edition_text} {version}, which is in the published affected range."

    return Finding(
        cve=cve,
        name=name,
        status=status,
        confidence=confidence,
        component=component,
        component_version=version,
        affected_rule=affected_rule,
        detail=detail,
        action=(
            remediation
            if status not in {"PATCHED", "NOT_AFFECTED"}
            else "No action is required for this CVE if version detection is accurate; keep AcyMailing maintained."
        ),
        evidence={"edition": edition or None, "source": info.get("source")},
    )


def passive_only_check(
    *,
    cve: str,
    name: str,
    affected_rule: str,
    fixed_version: str,
    plugins: dict | None,
    enterprise_only: bool,
    remediation: str,
    run_exploit_check: bool,
) -> Finding:
    finding = acymailing_finding(
        cve=cve,
        name=name,
        affected_rule=affected_rule,
        fixed_version=fixed_version,
        plugins=plugins,
        enterprise_only=enterprise_only,
        remediation=remediation,
    )
    if run_exploit_check and finding.status in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        finding.detail += " This module performs non-mutating version and edition assessment only."
    return finding


def metadata_base(
    *, cve: str, name: str, affected_rule: str, references: list[str], enterprise_only: bool
) -> dict[str, Any]:
    return {
        "cve": cve,
        "cms": "joomla",
        "name": name,
        "component": "AcyMailing Enterprise" if enterprise_only else "AcyMailing",
        "affected_rule": affected_rule,
        "affected_joomla_versions": ["*"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-03",
        "updated": "2026-10-03",
        "required_detectors": ["acymailing"],
        "references": references,
    }
