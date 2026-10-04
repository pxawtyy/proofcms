from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...core.models import Finding


def passive_core_finding(
    *,
    cve: str,
    name: str,
    affected_rule: str,
    joomla_version: str | None,
    classify: Callable[[str | None], str],
    remediation: str,
) -> Finding:
    status = classify(joomla_version)
    if status == "LIKELY_VULNERABLE":
        confidence = "HIGH"
        detail = f"Detected Joomla {joomla_version}, which is in the published affected range."
        action = remediation
    elif status == "PATCHED":
        confidence = "HIGH"
        detail = f"Detected Joomla {joomla_version}, which includes the published fix."
        action = "No action is required for this CVE if version detection is accurate."
    elif status == "NOT_AFFECTED":
        confidence = "HIGH"
        detail = f"Detected Joomla {joomla_version}, outside the published affected range."
        action = "No action is required for this CVE if version detection is accurate."
    else:
        confidence = "LOW"
        detail = "Joomla was detected, but its version could not be classified."
        action = remediation
    return Finding(
        cve=cve,
        name=name,
        status=status,
        confidence=confidence,
        component="Joomla core",
        component_version=joomla_version,
        affected_rule=affected_rule,
        exploit_available=False,
        detail=detail,
        action=action,
    )


def passive_component_finding(
    *,
    cve: str,
    name: str,
    component: str,
    affected_rule: str,
    detector_key: str,
    plugins: dict[str, Any] | None,
    classify: Callable[[str | None], str],
    remediation: str,
) -> Finding:
    extension = (plugins or {}).get(detector_key, {})
    if extension.get("state") == "error" or str(extension.get("source", "")).startswith("error:"):
        return Finding(
            cve=cve,
            name=name,
            status="ERROR",
            confidence="LOW",
            component=component,
            affected_rule=affected_rule,
            exploit_available=False,
            detail=f"{component} detection failed: {extension.get('source', 'unknown detector error')}",
            action="Resolve target connectivity or detector failure, then scan again.",
        )
    if not extension.get("found"):
        return Finding(
            cve=cve,
            name=name,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=component,
            affected_rule=affected_rule,
            exploit_available=False,
            detail=f"{component} was not detected through its public manifest or route.",
            action=f"Verify manually if the extension is installed but hidden. {remediation}",
        )

    version = extension.get("version")
    status = classify(version)
    if status == "LIKELY_VULNERABLE":
        confidence = "HIGH"
        detail = f"Detected {component} {version}, which is in the published affected range."
        action = remediation
    elif status in {"PATCHED", "NOT_AFFECTED"}:
        confidence = "HIGH"
        detail = f"Detected {component} {version}, outside the published affected range."
        action = "No action is required for this CVE if version detection is accurate."
    else:
        confidence = "MEDIUM"
        detail = (
            f"{component} was detected at {extension.get('source', 'an unknown source')}, but its version is unknown."
        )
        action = remediation
    return Finding(
        cve=cve,
        name=name,
        status=status,
        confidence=confidence,
        component=component,
        component_version=version,
        affected_rule=affected_rule,
        exploit_available=False,
        detail=detail,
        action=action,
    )


def passive_only_check(finding: Finding, run_exploit_check: bool) -> Finding:
    if run_exploit_check:
        finding.detail += " This module performs version-based assessment only; no active proof was sent."
    return finding
