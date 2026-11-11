from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe

PLUGIN_SLUG = "wpvivid-backuprestore"
COMPONENT = "WordPress plugin WPvivid Backup & Migration"


def classify_version(version: str | None, *, fixed: str) -> str:
    parsed = parse_version_safe(version)
    fixed_version = parse_version_safe(fixed)
    if parsed is None or fixed_version is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed_version else "PATCHED"


def passive_result(
    *,
    cve: str,
    name: str,
    affected_rule: str,
    plugins: dict[str, Any] | None,
    fixed: str,
    remediation: str,
    vulnerability_type: str | None = None,
) -> Finding:
    plugin = (plugins or {}).get(PLUGIN_SLUG, {})
    if not isinstance(plugin, dict) or not plugin.get("found"):
        return Finding(
            cve=cve,
            name=name,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=affected_rule,
            exploit_available=True,
            detail="WPvivid was not detected in public WordPress assets or metadata.",
            action=f"No action is required unless WPvivid is installed but hidden from public detection. {remediation}",
            vulnerability_type=vulnerability_type or "",
        )
    version = plugin.get("version")
    status = classify_version(version, fixed=fixed)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected WPvivid {version}, which is within the published affected range."
        confidence = "HIGH" if plugin.get("version_confidence", "HIGH") == "HIGH" else "MEDIUM"
        action = remediation
    elif status == "PATCHED":
        detail = f"Detected WPvivid {version}, which includes the published fix."
        confidence = "HIGH"
        action = "No action is required for this CVE if version detection is accurate."
    else:
        detail = (
            f"WPvivid was detected (version {version or 'unknown'}), "
            "but the exact version could not be determined."
        )
        confidence = "MEDIUM"
        action = remediation
    return Finding(
        cve=cve,
        name=name,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=affected_rule,
        exploit_available=True,
        detail=detail,
        action=action,
        vulnerability_type=vulnerability_type or "",
    )
