from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...core.models import Finding


def passive_plugin_finding(
    *,
    cve: str,
    name: str,
    component: str,
    affected_rule: str,
    plugin_slug: str,
    plugins: dict[str, Any] | None,
    classify: Callable[[str | None], str],
    remediation: str,
    exploit_available: bool = False,
) -> Finding:
    plugin = (plugins or {}).get(plugin_slug, {})
    if plugin.get("state") == "error" or str(plugin.get("source", "")).startswith("error:"):
        return Finding(
            cve=cve,
            name=name,
            status="ERROR",
            confidence="LOW",
            component=component,
            affected_rule=affected_rule,
            exploit_available=exploit_available,
            detail=f"Plugin detection failed: {plugin.get('source', 'unknown detector error')}",
            action="Resolve target connectivity or detector failure, then scan again.",
        )
    if not plugin.get("found"):
        return Finding(
            cve=cve,
            name=name,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=component,
            affected_rule=affected_rule,
            exploit_available=exploit_available,
            detail=f"The {component.removeprefix('WordPress plugin ')} plugin was not detected in public assets or metadata.",
            action=f"No action is required unless the plugin is installed but hidden from public detection. {remediation}",
        )

    version = plugin.get("version")
    status = classify(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected {component.removeprefix('WordPress plugin ')} {version}, which is in the affected range."
        confidence = "HIGH" if plugin.get("version_confidence", "HIGH") == "HIGH" else "MEDIUM"
    elif status == "PATCHED":
        detail = f"Detected {component.removeprefix('WordPress plugin ')} {version}, which includes the published fix."
        confidence = "HIGH" if plugin.get("version_confidence", "HIGH") == "HIGH" else "MEDIUM"
    elif status == "NOT_AFFECTED":
        detail = f"Detected {component.removeprefix('WordPress plugin ')} {version}, outside the published affected range."
        confidence = "HIGH" if plugin.get("version_confidence", "HIGH") == "HIGH" else "MEDIUM"
    else:
        detail = f"The {component.removeprefix('WordPress plugin ')} plugin was detected, but its version is unknown."
        confidence = "MEDIUM"

    return Finding(
        cve=cve,
        name=name,
        status=status,
        confidence=confidence,
        component=component,
        component_version=version,
        affected_rule=affected_rule,
        exploit_available=exploit_available,
        detail=detail,
        action=remediation if status in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"} else "No action is required for this CVE if version detection is accurate.",
    )


def passive_only_check(finding: Finding, run_exploit_check: bool) -> Finding:
    if run_exploit_check:
        finding.detail += " This module currently provides version-based assessment only; no active proof was sent."
    return finding
